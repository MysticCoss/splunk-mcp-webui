# Splunk MCP WebUI

MCP (Model Context Protocol) server cho Splunk — dựa trên các tool của Splunk MCP Server chính hãng, nhưng:

| | MCP chính hãng | Splunk MCP WebUI |
|---|---|---|
| Kết nối | splunkd REST API (port 8089) + token/app cài trong Splunk | **Splunk Web UI (port 8000)** — login bằng form như trình duyệt |
| Cấu hình | token, cert, app, roles... | **Chỉ 3 field: `splunk_url`, `username`, `password`** |
| Số tool | ~20 | **4 tool cốt lõi** |

Chỉ cần Splunk Web mở được là dùng được — không cần port quản trị 8089, không cần token, không cần cài app lên Splunk.

## Các tool

| Tool | Mô tả |
|---|---|
| `splunk_run_query` | Chạy SPL query, trả về kết quả JSON (mặc định 100 dòng, tự đánh dấu `truncated` nếu nhiều hơn) |
| `splunk_get_indexes` | Danh sách toàn bộ index (tên, kích thước, số event, splunk_server) |
| `splunk_get_index_info` | Thông tin chi tiết 1 index |
| `splunk_get_metadata` | Metadata `hosts` / `sources` / `sourcetypes` theo index và khoảng thời gian |

## Cài đặt

```powershell
cd C:\Users\vitco\splunk-mcp-webui
pip install -r requirements.txt
```

## Cấu hình

Copy `config.example.json` thành `config.json` (cùng thư mục với project) rồi sửa:

```json
{
  "splunk_url": "https://splunk-cua-ban",
  "username": "admin",
  "password": "mat-khau"
}
```

> `config.json` chứa credential thật nên đã bị `.gitignore` loại khỏi repo — chỉ commit `config.example.json`.

## SSL self-signed

Mặc định client **chấp nhận mọi chứng chỉ SSL** — kể cả self-signed, cert nội bộ hay cert tự ký của Splunk:

```json
{
  "verify_ssl": false
}
```

Đây là giá trị mặc định, không cần khai báo trong `config.json`. Chỉ khi muốn xác thực chứng chỉ nghiêm ngặt (ví dụ Splunk dùng cert CA hợp lệ) thì mới đặt:

```json
{
  "verify_ssl": true
}
```

Đó là tất cả. Mọi thứ khác tự xử lý: tự detect `http/https`, locale (`en-US`...), session cookie, CSRF form-key, tự re-login khi session hết hạn, SSL self-signed được tự động chấp nhận.

> `splunk_url` chấp nhận mọi dạng: `splunk.corp.local`, `http://10.0.0.5:8000`, `https://splunk.corp.local:8000/en-US`.
> Mật khẩu nằm trong file plain-text — hạn chế quyền đọc file nếu cần. Có thể đặt đường dẫn khác qua biến môi trường `SPLUNK_MCP_CONFIG`.

## Kiểm tra kết nối trước khi dùng

```powershell
python tests\test_real.py
```

## Đăng ký vào MCP client

### Claude Code

```powershell
claude mcp add splunk-webui -s user -- python C:\duong\dan\splunk-mcp-webui\run.py
```

- `-s user`: cài cấp user, dùng được cho mọi project trên máy. Bỏ tham số này thì chỉ áp dụng cho project hiện tại.
- Kiểm tra: mở Claude Code, gõ `/mcp` — phải thấy `splunk-webui` kèm 4 tool.

### Claude Desktop / opencode

Thêm vào file cấu hình MCP của client:

```json
{
  "mcpServers": {
    "splunk-webui": {
      "command": "python",
      "args": ["C:\\duong\\dan\\splunk-mcp-webui\\run.py"]
    }
  }
}
```

Chạy trực tiếp (stdio): `python run.py` hoặc `python -m splunk_mcp_webui`.

## Cách hoạt động

```
MCP client ──stdio──> run.py ──HTTP──> Splunk Web (port 8000)
                         │ 1. GET  /en-US/account/login        → cookie + CSRF
                         │ 2. POST /en-US/account/login        → session cookie
                         │ 3. POST /en-US/splunkd/__raw/services/search/jobs  → tạo job
                         │ 4. GET  /en-US/splunkd/__raw/services/search/jobs/{sid} → poll
                         │ 5. GET  .../{sid}/results           → kết quả JSON
```

Không dùng port 8089 — mọi REST call đi qua proxy `splunkd/__raw/` của chính Splunk Web (giống hệt khi bạn mở Search & Reporting trên trình duyệt).

## Test offline (không cần Splunk thật)

```powershell
python tests\test_offline.py      # 16 test: login, CSRF, search job, 404, re-login...
python tests\test_mcp_server.py   # test 4 tool qua giao thức MCP
```

Thư mục `ref\` chứa bản giải nén `splunk-mcp-server_200.tgz` (app chính hãng) dùng làm tham chiếu schema cho 4 tool.
