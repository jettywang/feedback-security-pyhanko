# “PDF 里有 DSS，补一个时间戳就能长效验证” —— 用 pyHanko 实现核对

结论先行：**这句话不成立。** 时间戳本身只证明“某一修订里的字节在某时刻已存在”，
长效（LTA）验证能否成立，取决于**撤销材料（CRL/OCSP）和链证书是否在被某个
文档时间戳覆盖的修订里、且在该时间戳的 POE（存在性证明）时间点可用**。
材料在时间戳之后才进 DSS，旧时间戳保护不到它；落在错误的 VRI 记录下则
**在 pyHanko 验证器里完全不影响结果**，因为 pyHanko 只读 DSS 全局池，不读 VRI 键。

本目录所有实验均离线运行（certomancer 测试 PKI + `DummyTimeStamper` + `freezegun`），
不依赖网络或本地端口。复现：`../.venv/bin/python run_matrix.py`（另见 `run_ocsp_vri.py`、
`run_salvage.py`、`scenario_a.py`）。

---

## 1. pyHanko 的实际机制（源码层面）

### 1.1 POE 是按“修订号”累积的，时间戳只覆盖它之前的 DSS

`_build_prima_facie_poe_index_from_pdf_timestamps` 按修订顺序遍历签名，遇到文档时间戳时，
用 `HistoricalResolver(r, revision=embedded_sig.signed_revision)` 取**该时间戳所在修订**
的 DSS 快照，把其中的 CRL/OCSP/证书登记为该时间戳时刻的 POE：

- `pkgs/pyhanko/src/pyhanko/sign/validation/ades.py:1761`（历史解析器定位到签名修订）
- `pkgs/pyhanko/src/pyhanko/sign/validation/ades.py:1793`（`read_dss(hist_handler)`）
- 之后 `for_next_ts` 才被清空（`ades.py:1818`），时间戳之后新出现的对象进入**下一个**
  时间戳的集合，不会回填给当前时间戳。

含义：**修订 N 才加入 DSS 的 CRL/OCSP，不可能被修订 M<N 的时间戳证明存在。**

### 1.2 过去验证里，撤销材料有两道“时间门”

time-slide（AdES 过去验证）挑选 CRL/OCSP 时同时要求“签发不晚于控制时间”且
“该材料的 POE 不晚于控制时间”，否则直接跳过：

- CRL：`pkgs/pyhanko-certvalidator/src/pyhanko_certvalidator/revinfo/validate_crl.py:905`
  （`issued > control_time or poe_manager[...] > control_time` → `continue`）
- OCSP：`pkgs/pyhanko-certvalidator/src/pyhanko_certvalidator/revinfo/validate_ocsp.py:658`
  （同一条件）

而 `POEManager.__getitem__` 对**没有任何已登记 POE 的对象，会顺手把“当前时间”登记为
其 POE**（`pkgs/pyhanko-certvalidator/src/pyhanko_certvalidator/ltv/poe.py:219`，
docstring 明确写了这个副作用是有意的）。于是时间戳之后才进 DSS 的材料，在过去验证中
其 POE = 验证当下，必然晚于被回溯的控制时间而被排除。

### 1.3 VRI 不参与验证作用域，只读全局 `/Certs /CRLs /OCSPs`

- 验证侧把 DSS 整体灌进 `LocalKnowledge`，遍历的是 `dss.crls / dss.ocsps / dss.load_certs()`
  这些**全局池**，从未按 VRI 键过滤：`ades.py:2103`（`_dss_to_local_knowledge`）。
- `dss.py` 里 VRI 只在**写入**时生成（`register_vri`，`dss.py:198`），`read_dss` 仅浅拷贝
  VRI 字典备用（`dss.py:361`），没有任何“某签名只能用某 VRI”的判定。
- 官方注释直接称 VRI 是“relic of the past … effectively deprecated … most modern
  validators don't rely on it”：`pkgs/pyhanko/src/pyhanko/sign/signers/pdf_signer.py:108`。

含义：材料挂在错误签名的 VRI 键下，只要同时进了 DSS 全局池，pyHanko 照样使用。
VRI 放错是**互操作性/合规瑕疵**，不是 pyHanko 的验证失败原因。

### 1.4 两个容易踩的附加前提

- AdES 带时间验证要求签名容器内有**签名时间戳**（signature timeStamp），否则直接
  `SIG_CONSTRAINTS_FAILURE / "No signature timestamp present"`（`ades.py:1134`）。
  文档时间戳不能替代签名时间戳。
- CRL/OCSP 还有“新鲜度”判定。长效策略应用
  `FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION`（pyHanko 自测同款），并把验证上下文
  设为 `RevinfoOnlineFetchingRule.LOCAL_ONLY`，否则过期 CRL 会触发联网抓取/陈旧失败。

---

## 2. 修订顺序图（本地证书 + 本地时间戳样例）

时间线（UTC）：签名 2020-11-20 → DSS 2021-05-25 → DTS1 2021-06-01 →（可选）晚到 DSS
2021-09-01 → DTS2 2021-09-05。`Rk` 为 PDF 增量修订号。

```
正确归档（场景 A，2021-06-05 验证 => AdESPassed.OK）
R1  PAdES 签名 + 签名时间戳(TSA1)        [/Sig, 无 DSS]
R2  DSS：Root/Interm/TSA 证书 + interm CRL + root CRL（全局池）
R3  文档时间戳 DTS1  ── 覆盖 R1..R2 全部字节 => 为 R2 的 CRL/证书签发 POE(2021-06-01)
        过去验证：控制时间回拨到 2020-11-20，CRL 的 POE=2021-06-01 早于…可用于旧签名 ✓

材料晚到（场景 B，2021-06-05 验证 => NO_POE）
R1  PAdES 签名 + 签名时间戳
R2  文档时间戳 DTS1                      [此刻 DSS 不存在，POE 集合里没有任何 CRL/OCSP]
R3  DSS：证书 + 两张 CRL（2021-09 才写入）
        DTS1 的 POE 不含 R3 材料 => 旧签名在 6 月拿不到撤销证据 ✗
        （2021-09 CRL 窗口内做“当前时间验证”可 OK，但材料不受 DTS1 保护，
         无法支撑 2020 签名时刻的历史结论）

补救（场景 G）：R3 之后再加 R4 文档时间戳 DTS2
        DTS2 为晚到 CRL 签发 POE(2021-09)；链得以延续，但旧签名的“最早证据时间”
        取决于最早能覆盖到所需材料的那个时间戳，材料缺口期无法回填。

VRI 放错（场景 C/C2，验证 => OK）
        全局 /Certs /CRLs 齐全即通过；VRI 键指向 DocTS 而非 /Sig 不改变 pyHanko 结果。
```

---

## 3. 实测矩阵（`run_matrix.py` / `run_ocsp_vri.py`）

验证策略：`REQUIRE_REVINFO` + `MAX_DIFF_REVOCATION_VALIDATION` + `LOCAL_ONLY`，
信任根为测试 Root CA。

| 场景 | DSS 材料相对时间戳 | VRI 键 | 2021-06-05（CRL 窗口内） | 说明 |
|---|---|---|---|---|
| A | 全部**之前** | 无 | `OK`，best=2020-11-20 | 材料有 POE，过去验证成立 |
| B | 全部**之后** | 无 | `NO_POE` | DTS1 的 POE 集合无撤销材料 |
| C | 之后 | 指向 DocTS（错） | `OK`* | 靠当前时间验证；POE 仍缺，非历史可证 |
| C2 | 池在之前，仅 VRI 错 | 指向 DocTS（错） | `OK`，best=2020-11-20 | 证明 VRI 键不参与作用域 |
| D | 无 DSS | — | `CERTIFICATE_CHAIN_GENERAL_FAILURE` | 完全无撤销材料 |
| E | 之前（叶子用 **OCSP** + root CRL） | 无 | `OK` | OCSP 与 CRL 等效，同样需在 TS 前 |
| F | 之前 | 指向 /Sig（正确） | `OK` | 正确 VRI 的对照组 |

\* C 在 CRL 仍新鲜的当前时间窗口能过，是因为“当前时间验证”不依赖历史 POE；
一旦进入需要 time-slide 的过去验证（叶子过期后），它与 B 一样失败。

续签节奏实验（`scenario_a.py` 的双时间戳版与上游测试 `test_simulate_future_lta_*`）另证明：
**时间戳链必须在 TSA 证书或 CRL 失效前持续延长**。TSA1 证书 2030 到期、CRL 仅 30/90 天
有效；断档后 pyHanko 返回 `OUT_OF_BOUNDS_NO_POE` / `NO_POE`，与上游
`test_simulate_future_lta_with_broken_ts_chain`、`test_pades_lta_expired_timestamp` 一致。

---

## 4. 可执行的续签前检查清单

### A. 证据充分、可以继续续签（同时满足）
- [ ] 每个待保签名的容器内有**签名时间戳**（否则先补，避免 `SIG_CONSTRAINTS_FAILURE`）。
- [ ] 签名链上**每张证书**（叶子、中间 CA、TSA、OCSP 应答者如适用）都能在 DSS 全局
      `/Certs` 找到，且撤销材料覆盖到**根的直接下级**（本实验即 root CRL 覆盖 interm 与 TSA，
      interm CRL/OCSP 覆盖叶子）。
- [ ] 上述 CRL/OCSP 与链证书都出现在**某个文档时间戳所在修订或更早**的 DSS 快照里
      （即被该时间戳的 POE 覆盖）。用本仓库 `lab_lib.poe_map` 核对：目标时间戳的
      `POE objects` 里应能数到对应的 `CRL`/`OCSP`/`CERTIFICATE`。
- [ ] 撤销材料在其自身 `thisUpdate..nextUpdate` 窗口内被时间戳覆盖；策略用
      `MAX_DIFF_REVOCATION_VALIDATION`，验证用 `LOCAL_ONLY` 跑通 `ades_lta_validation => OK`。
- [ ] 时间戳链无断档：下一个 DTS 的 genTime 早于当前 TSA 证书 `notAfter` 与所有在用
      CRL 的 `nextUpdate`。
- [ ] （可选合规项）VRI 键 = 签名 Contents 的 SHA-1 大写十六进制（`sig_content_identifier`），
      指向正确签名；放错不影响 pyHanko，但影响严格合规校验与其他验证器互操作。

### B. 证据不足、必须先补材料（命中任一即停）
- [ ] DSS 缺失，或只有证书没有 CRL/OCSP（场景 D）→ 先补撤销材料再盖时间戳。
- [ ] 撤销材料在**最近一个文档时间戳之后**的修订才加入（场景 B，`NO_POE`）→
      必须再追加一个新的文档时间戳来覆盖这些材料，旧时间戳无法回填。
- [ ] 链不完整（如缺 root CRL，导致“CRL issuer Intermediate CA path could not be
      validated”）→ 补齐颁发者侧撤销材料。
- [ ] CRL/OCSP 已过 `nextUpdate` 且无更新鲜材料、或时间戳链断档（`OUT_OF_BOUNDS_NO_POE`、
      `NO_POE`、`StaleRevinfoError`）→ 在失效前刷新材料并延长 DTS 链。
- [ ] 验证仍尝试联网（日志出现 `Retrieving CRLs ... pyhanko.tests`）→ 说明策略未设
      `LOCAL_ONLY`，离线归档不可接受，先修策略再判定。
- [ ] 仅“当前时间验证 OK”但 `oldest_evidence_record_timestamp` 为 None 或早于材料入档 →
      历史可证性不成立，不能据此声称长效有效。

### C. 一句话判据
> 续签前问一句：**“这份 CRL/OCSP 和这张证书，是否已经躺在某个文档时间戳覆盖得到的
> 修订里？”** 是 → 证据可用于旧签名，可继续；否 → 先补材料、再用新时间戳覆盖，
> 顺序反了就得靠下一个时间戳补救，且缺口期无法追溯。
