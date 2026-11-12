# DSS / 时间戳 / 撤销材料排序实验（离线）

用 pyHanko 自带的 certomancer 测试 PKI 与 `DummyTimeStamper`，全程不联网、不监听端口。
需要仓库根目录的虚拟环境：`../.venv`。

## 运行

```
../.venv/bin/python run_matrix.py      # 场景 A/B/C/C2/D：材料在时间戳前/后/错误 VRI/无 DSS
../.venv/bin/python run_ocsp_vri.py    # 场景 E（OCSP 等效）/ F（正确 VRI）
../.venv/bin/python run_salvage.py     # 场景 G：晚到材料 + 后续时间戳补救
```

每个脚本会把生成的 PDF 写到 `artifacts/`，并打印修订地图（`revision_map`）与
每个文档时间戳覆盖到的 POE 对象（`poe_map`）。结论与续签检查清单见 `REPORT.md`。

## 文件

- `pki_common.py`：测试 PKI 句柄、冻结时间点、离线 ValidationContext 与 LTA 验证策略。
- `lab_lib.py`：签名 / 加 DSS / 加文档时间戳 / 修订与 POE 检视原语。
- `run_*.py`：可执行场景。
