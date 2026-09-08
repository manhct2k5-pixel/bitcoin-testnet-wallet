# Hướng dẫn quy trình tạo và gửi giao dịch Bitcoin UTXO

Tài liệu này giải thích cách sử dụng dự án và toàn bộ luồng xử lý một giao dịch Bitcoin từ private key. Dự án được cấu hình cho **Bitcoin Testnet3**, phù hợp để học tập và trình diễn mà không sử dụng BTC thật.

> **Bảo mật:** Không chia sẻ private key hoặc WIF. Người có WIF có thể ký giao dịch và sử dụng toàn bộ UTXO của ví. Chỉ dùng các khóa trong dự án này trên Testnet.

## 1. Tổng quan quy trình

```text
Private Key
→ Derive Addresses
→ Find UTXOs
→ Coin Selection
→ Build Unsigned Transaction
→ Hash từng input
→ Sign
→ Build Signed Transaction
→ Serialize raw transaction hex
→ Broadcast
→ Theo dõi TXID và UTXO mới
```

Bitcoin sử dụng mô hình **UTXO**. Số dư của một ví là tổng các UTXO mà private key của ví có quyền chi tiêu. Có thể hiểu mỗi UTXO là một “mảnh coin” riêng, được xác định bằng cặp:

```text
txid:vout
```

- `txid`: mã giao dịch đã tạo ra UTXO.
- `vout`: vị trí của output trong giao dịch đó.
- `value`: giá trị UTXO, tính bằng satoshi.
- `scriptPubKey`: điều kiện khóa số tiền.

Một giao dịch mới tiêu các UTXO cũ làm input và tạo ra các UTXO mới ở output.

## 2. Tạo hoặc nhập ví

Giao diện hỗ trợ hai thao tác:

- **Tạo ví Testnet mới:** chương trình sinh một private key ngẫu nhiên.
- **Nhập WIF:** chương trình giải mã private key Testnet đã có.

WIF là định dạng Base58Check dùng để biểu diễn private key. WIF Testnet thường bắt đầu bằng `c` hoặc `9`.

Backend kiểm tra:

1. Chuỗi có phải Base58 hợp lệ hay không.
2. Checksum có đúng hay không.
3. Prefix có thuộc Bitcoin Testnet hay không.
4. Private key có nằm trong miền hợp lệ của `secp256k1` hay không.

Lỗi sau cho biết WIF chứa ký tự không thuộc bảng Base58:

```text
Invalid Base58 character: '0'
```

Base58 loại bỏ các ký tự dễ nhầm như `0`, `O`, `I` và `l`.

## 3. Suy ra các địa chỉ từ private key

Từ private key, chương trình tạo public key trên đường cong `secp256k1`, sau đó suy ra 5 loại địa chỉ.

| Loại địa chỉ | Prefix Testnet thường gặp | Đặc điểm |
|---|---|---|
| P2PKH compressed | `m` hoặc `n` | Legacy, dùng public key nén |
| P2PKH uncompressed | `m` hoặc `n` | Legacy, dùng public key không nén |
| P2SH-P2WPKH | `2` | SegWit được bọc trong P2SH |
| P2WPKH | `tb1q` | Native SegWit, thường tiết kiệm kích thước hơn Legacy |
| P2TR key-path | `tb1p` | Taproot, sử dụng chữ ký Schnorr |

Một private key kiểm soát được nhiều địa chỉ vì mỗi loại địa chỉ sử dụng cách biểu diễn public key hoặc locking script khác nhau.

## 4. Kiểm tra số dư và danh sách UTXO

Khi bấm **Kiểm tra số dư & danh sách UTXO**, frontend gửi WIF đến:

```text
POST /api/balance/all
```

Backend thực hiện:

1. Kiểm tra WIF.
2. Suy ra cả 5 loại địa chỉ.
3. Truy vấn Esplora Testnet API cho từng địa chỉ.
4. Lấy danh sách UTXO của từng địa chỉ.
5. Gộp và loại bỏ UTXO trùng lặp.
6. Tính số dư tổng, số dư đã xác nhận và số dư đang chờ.

Mỗi UTXO trên giao diện có:

- `txid` và `vout`.
- Giá trị tính bằng satoshi.
- Địa chỉ sở hữu.
- Loại địa chỉ.
- Trạng thái đã xác nhận hoặc đang chờ.
- Liên kết mở giao dịch trên Mempool Testnet.

Các chỉ số số dư:

- **Tổng số dư:** confirmed + pending.
- **Đã xác nhận:** UTXO đã nằm trong block.
- **Đang chờ:** UTXO đang nằm trong mempool.
- **Số UTXO:** tổng số “mảnh coin” của ví.
- **Số dư từng địa chỉ:** cho biết UTXO nằm ở loại địa chỉ nào.

Ví dụ:

```text
UTXO A = 100.000 sat
UTXO B = 50.000 sat
UTXO C = 20.000 sat

Tổng số dư = 170.000 sat
Số UTXO = 3
```

## 5. Nhập thông tin giao dịch

Phần **Tạo và gửi giao dịch** yêu cầu:

- **Ví gửi:** private key WIF Testnet.
- **Địa chỉ nhận:** địa chỉ Testnet hợp lệ.
- **Số tiền gửi:** nhập theo satoshi hoặc BTC.
- **Phí cố định:** số satoshi dành cho miner.

Quy đổi:

```text
1 BTC = 100.000.000 satoshi
```

Ví dụ:

```text
Số tiền gửi = 12.000 sat
Phí = 300 sat
Tổng tối thiểu cần có = 12.300 sat
```

Số tiền và phí phải là số nguyên dương khi nhập theo satoshi.

## 6. Xem trước giao dịch

Khi bấm **Xem trước UTXO**, giao diện sẽ tự động:

1. Kiểm tra WIF, địa chỉ nhận, số tiền và phí.
2. Gọi API để tải UTXO của cả 5 địa chỉ.
3. Chọn UTXO đủ để thanh toán.
4. Tính output người nhận, change và phí thực tế.
5. Hiển thị UTXO trước và sau giao dịch.

Thông báo sau xác nhận đây chỉ là mô phỏng:

```text
Đây là bản xem trước. Chưa ký và chưa broadcast giao dịch.
```

Ở bước xem trước, private key chưa được dùng để tạo chữ ký và tiền chưa được gửi.

## 7. Coin selection

Chương trình sắp xếp UTXO từ giá trị lớn đến nhỏ, sau đó lấy lần lượt cho đến khi:

```text
Tổng input >= số tiền gửi + phí
```

Cách chọn này ưu tiên dùng ít input. Ít input giúp transaction nhỏ hơn và thường tiết kiệm phí hơn.

Ví dụ ví có:

```text
UTXO A = 100.000 sat
UTXO B = 20.000 sat
UTXO C = 10.000 sat
```

Muốn gửi `12.000 sat` với phí `300 sat`, chương trình chỉ cần chọn UTXO A:

```text
Input       = 100.000 sat
Người nhận  = 12.000 sat
Change      = 87.700 sat
Phí         = 300 sat
```

Mọi giao dịch phải thỏa mãn:

```text
Tổng input = tiền người nhận + change + phí
```

## 8. Cách đọc sơ đồ UTXO trên giao diện

### Trước giao dịch

- UTXO màu xanh là UTXO hiện có.
- UTXO màu đỏ là UTXO được chọn làm input và sẽ bị tiêu.
- UTXO không được chọn vẫn thuộc ví sau giao dịch.

### Transaction ở giữa

Khu vực này hiển thị:

- Số input được chọn.
- Số output được tạo.
- Tổng giá trị input.
- Số tiền gửi.
- Change.
- Phí thực tế.
- Kích thước transaction sau khi ký, nếu đã có.

### Sau giao dịch

- Output người nhận là số tiền chuyển đến địa chỉ đích.
- Change output là tiền thừa trả về ví gửi.
- Các UTXO không được chọn tiếp tục tồn tại.

Trong chế độ xem trước, các output sau giao dịch mới là kết quả dự kiến. Chúng trở thành UTXO thực sau khi transaction được node chấp nhận.

## 9. Change output và dust

Nếu tổng input lớn hơn tiền gửi cộng phí, chương trình tạo change output:

```text
Change = tổng input - số tiền gửi - phí
```

Ví dụ:

```text
Input  = 20.000 sat
Gửi    = 10.000 sat
Phí    = 300 sat
Change = 9.700 sat
```

Transaction tạo hai output:

```text
Output 0: 10.000 sat → người nhận
Output 1: 9.700 sat  → ví gửi
```

Nếu change nhỏ hơn ngưỡng dust đang áp dụng, chương trình không tạo change output. Phần dư nhỏ đó được cộng vào phí thực tế. Dự án hiện dùng ngưỡng change khoảng `294 sat`.

## 10. Tạo nhiều UTXO bằng cách gửi về chính ví

Nút **Gửi về ví này để tạo thêm UTXO** điền địa chỉ P2WPKH của chính ví vào ô địa chỉ nhận.

Ví dụ ví có một UTXO `100.000 sat`, sau đó gửi cho chính mình `10.000 sat` với phí `300 sat`:

```text
UTXO người nhận = 10.000 sat
UTXO change     = 89.700 sat
Tổng mới        = 99.700 sat
```

Ví có thể chuyển từ 1 UTXO thành 2 UTXO, nhưng tổng số dư giảm `300 sat` do phí mạng. Gửi về chính mình không làm tăng số tiền.

Sau mỗi lần gửi, cần đợi transaction xuất hiện trên mempool hoặc được xác nhận trước khi tiếp tục dùng output mới.

## 11. Xây dựng unsigned transaction

Sau coin selection, backend tạo transaction chưa ký gồm:

```text
version
inputs
outputs
locktime
```

Mỗi input chứa:

```text
txid của UTXO cũ
vout của UTXO cũ
sequence
scriptSig tạm thời
witness tạm thời
```

Mỗi output chứa:

```text
value
scriptPubKey của địa chỉ nhận
```

Một transaction chỉ có một cấu trúc tổng thể nhưng mỗi input có message hash riêng để ký. Bước này được thực hiện trong hàm `build_unsigned_transaction` của `main.py`.

## 12. Tạo hash cần ký cho từng input

Cách tạo signature hash phụ thuộc loại UTXO.

### P2PKH

Sử dụng legacy signature hash. Script của UTXO đang ký được đưa vào dữ liệu băm, sau đó dữ liệu được double SHA-256.

### P2SH-P2WPKH và P2WPKH

Sử dụng BIP143. Dữ liệu băm bao gồm outpoint, sequence, input đang ký, giá trị UTXO, script code, outputs, locktime và sighash type.

### P2TR

Sử dụng Taproot signature hash theo BIP341. Dữ liệu bao gồm thông tin input, giá trị, scriptPubKey, sequence, output và các trường Taproot liên quan.

Kết quả của mỗi lần băm là một message hash 32 byte.

## 13. Ký từng input

### ECDSA

Các input P2PKH, P2SH-P2WPKH và P2WPKH sử dụng ECDSA trên `secp256k1`:

- Nonce xác định theo RFC6979.
- Chữ ký được mã hóa strict DER.
- Giá trị `S` được chuẩn hóa về low-S.
- Chữ ký được gắn sighash type, thông thường là `SIGHASH_ALL`.

### Schnorr

Input P2TR sử dụng:

- Schnorr signature theo BIP340.
- Taproot key tweak.
- Signature hash theo BIP341.

Phần ký nằm trong hàm `sign_transaction` của `main.py`.

## 14. Gắn chữ ký vào input

| Loại input | `scriptSig` | Witness |
|---|---|---|
| P2PKH | Chữ ký + public key | Không có |
| P2SH-P2WPKH | Redeem script | Chữ ký + public key |
| P2WPKH | Trống | Chữ ký + public key |
| P2TR | Trống | Schnorr signature |

Một transaction có thể chứa nhiều loại input cùng lúc. Backend tạo đúng signature hash và dữ liệu mở khóa tương ứng cho từng input.

## 15. Serialize thành raw transaction hex

Sau khi gắn chữ ký, chương trình serialize transaction thành byte theo định dạng Bitcoin rồi chuyển thành chuỗi hexadecimal.

Raw transaction chứa:

- Version.
- Danh sách input.
- Danh sách output.
- `scriptSig`.
- Witness.
- Sequence.
- Locktime.

Transaction có SegWit sẽ chứa marker và flag `00 01`. Chuỗi raw hex là dữ liệu thực tế được gửi đến Bitcoin node.

## 16. Broadcast lên Bitcoin Testnet

Khi bấm **Ký và broadcast giao dịch**, frontend gọi:

```text
POST /api/send
```

Backend chạy toàn bộ quy trình:

```text
Kiểm tra dữ liệu
→ Derive 5 địa chỉ
→ Tải UTXO
→ Coin selection
→ Tạo unsigned transaction
→ Hash từng input
→ Ký từng input
→ Gắn scriptSig/witness
→ Serialize raw hex
→ Broadcast
```

Raw transaction được gửi qua Esplora Testnet API. Nếu thành công, giao diện hiển thị:

- TXID.
- Raw transaction hex.
- Link Mempool Testnet.
- UTXO đã tiêu.
- Output người nhận.
- Change output.
- Phí thực tế.
- Kích thước transaction.

## 17. Trạng thái sau broadcast

Ngay sau khi node chấp nhận giao dịch:

- Transaction xuất hiện trong mempool.
- Các input đã chọn được transaction sử dụng.
- Output mới có trạng thái pending.
- Số xác nhận bằng 0.

Khi miner đưa giao dịch vào block:

- Transaction có ít nhất 1 confirmation.
- Output mới trở thành UTXO đã xác nhận.
- Số dư tương ứng chuyển từ pending sang confirmed.

Bấm lại **Kiểm tra số dư & danh sách UTXO** để tải trạng thái mới.

## 18. Các lỗi thường gặp

### Không tìm thấy UTXO

```text
No UTXOs found. Fund one of the derived Testnet addresses first.
```

WIF hợp lệ nhưng cả 5 địa chỉ chưa có UTXO. Cần gửi Testnet coin đến một trong các địa chỉ được suy ra.

### Không đủ tiền

```text
Not enough funds: have 10000 sat, need 100300 sat
```

Ví có `10.000 sat` nhưng giao dịch cần `100.300 sat`, gồm `100.000 sat` tiền gửi và `300 sat` phí. Cần giảm số tiền hoặc nạp thêm Testnet coin.

### Số tiền bằng 0

```text
Satoshi phải là số nguyên dương.
```

Số tiền gửi phải lớn hơn 0. Output quá nhỏ cũng có thể bị node từ chối do dust.

### Yêu cầu kiểm tra UTXO trước

Thông báo cũ:

```text
Hãy bấm “Kiểm tra UTXO của 5 địa chỉ” trước.
```

Luồng này đã được cập nhật. Nút **Xem trước UTXO** hiện tự tải số dư và UTXO nếu dữ liệu chưa có hoặc WIF đã thay đổi.

## 19. Kịch bản trình bày dự án

1. Mở ứng dụng và xác nhận đang dùng Testnet3.
2. Tạo hoặc import một WIF Testnet.
3. Chỉ ra 5 loại địa chỉ được suy ra từ cùng một private key.
4. Bấm **Kiểm tra số dư & danh sách UTXO**.
5. Giải thích tổng số dư, confirmed, pending và số lượng UTXO.
6. Mở chi tiết từng UTXO để xem `txid:vout`, giá trị và loại địa chỉ.
7. Nhập địa chỉ nhận, số tiền và phí.
8. Bấm **Xem trước UTXO**.
9. Chỉ ra UTXO nào được chọn làm input và UTXO nào được giữ lại.
10. Giải thích output người nhận, change output và phí.
11. Kiểm tra phương trình `tổng input = tiền gửi + change + phí`.
12. Xác nhận trạng thái xem trước chưa ký và chưa broadcast.
13. Bấm **Ký và broadcast giao dịch**.
14. Theo dõi nhật ký các bước tạo, hash, ký, serialize và broadcast.
15. Mở TXID trên Mempool Testnet.
16. Kiểm tra lại số dư và danh sách UTXO sau giao dịch.

## 20. Các tệp chính trong dự án

- `main.py`: xử lý khóa, địa chỉ, UTXO, coin selection, tạo transaction, ký, serialize và broadcast.
- `app.py`: cung cấp Flask API cho frontend.
- `templates/index.html`: giao diện ví, số dư, danh sách UTXO và sơ đồ trước/sau giao dịch.
- `tests/test_bitcoin_flow.py`: kiểm thử encoding, chữ ký, coin selection, transaction và API số dư.
- `requirements.txt`: danh sách thư viện Python cần cài đặt.

