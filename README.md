# Bitcoin Testnet UTXO Transaction Builder

Đây là ví minh họa quy trình tạo, ký và broadcast giao dịch Bitcoin theo mô
hình UTXO. Chương trình khóa địa chỉ và WIF ở **Bitcoin Testnet/Signet** để hạn
chế việc vô tình sử dụng tiền thật. API mặc định hiện kết nối Bitcoin Testnet.

Các loại địa chỉ single-key được hỗ trợ đầy đủ ở cả bước tìm UTXO và ký input:

- P2PKH Legacy với public key compressed;
- P2PKH Legacy với public key uncompressed;
- P2SH-P2WPKH (SegWit bọc);
- P2WPKH (native SegWit);
- P2TR Taproot key-path, không có script tree.

Một private key không thể tự suy ra mọi địa chỉ script có thể tồn tại. Những
loại như multisig P2SH/P2WSH hoặc Taproot script-path còn cần redeem script,
witness script, descriptor hoặc Taproot script tree. Vì vậy chúng nằm ngoài
phạm vi ví single-key này.

## Luồng xử lý

1. `keys.py` kiểm tra WIF, suy ra public key và năm dạng địa chỉ.
2. `network.py` gọi Esplora Testnet để lấy toàn bộ UTXO của từng địa chỉ.
3. `select_utxos()` sắp xếp UTXO giảm dần để đạt số input tối thiểu.
4. `build_unsigned_transaction()` tạo input, output nhận và change P2WPKH;
   tại thời điểm này toàn bộ `scriptSig` và witness vẫn trống.
5. `sign_transaction()` tạo sighash riêng cho từng input: legacy, BIP143 hoặc BIP341.
6. Hàm ký sau đó gắn ECDSA DER low-S hoặc Schnorr BIP340 vào đúng
   `scriptSig`/witness; `build_signed_transaction()` chỉ là hàm bao hai bước này.
7. Transaction được serialize, bao gồm `scriptSig` và witness tương ứng.
8. `network.broadcast_tx()` gửi raw transaction hex lên Bitcoin Testnet.

Giao diện có sơ đồ **UTXO trước và sau giao dịch**: UTXO được chọn được đánh dấu
đã tiêu, các UTXO không được chọn được giữ nguyên, và hai output mới (người nhận
và change) được hiển thị cùng phép tính `total input = amount + change + fee`.

Nếu phần dư nhỏ hơn ngưỡng dust 294 sat của change P2WPKH, chương trình không
tạo change output và ghi rõ phần đó được cộng vào phí thực tế.

## Chạy ứng dụng

### Windows PowerShell

```powershell
cd D:\files1
python3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Không cần kích hoạt virtual environment khi gọi trực tiếp `python.exe` như
trên. Nếu máy chỉ có lệnh `py`, thay `python3` bằng `py`.

### Linux/macOS

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
```

Mở `http://127.0.0.1:5000`, tạo/import Testnet WIF, nạp test coin từ faucet,
rồi gửi đến một địa chỉ Testnet hợp lệ.

## Chạy kiểm thử

```bash
python3 -m unittest discover -s tests -v
```

Bộ test không truy cập mạng và không broadcast thật. Nó kiểm tra checksum,
phân biệt Mainnet/Testnet, coin selection, dust/change, giao dịch input hỗn hợp,
test vector BIP143, BIP340 và Taproot tweak BIP341.
