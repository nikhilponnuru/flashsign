# flashsign

High-performance PDF signing library and CLI for Go.

## Build

```bash
go build -o flashsign ./cmd/flashsign/
```

## Modes

### 1. Legacy CLI (sign)

```bash
./flashsign sign \
  -pfx testdata/test.pfx -pfx-pass test123 \
  -src testdata/test.pdf -dest /tmp/signed.pdf
```

### 2. Legacy CLI (sign + encrypt)

```bash
./flashsign encrypt \
  -pfx testdata/test.pfx -pfx-pass test123 \
  -src testdata/test.pdf -dest /tmp/encrypted.pdf \
  -password secret123
```

### 3. HTTP Server

Create a `config.ini`:

```ini
keyfile=testdata/test.pfx
password=test123
reason=Testing
contact=Test
location=Test
page=1
x1=0
y1=609
x2=278
y2=550
server=true
server_port=8009
server_host=localhost
```

Start the server:

```bash
./flashsign -config config.ini
```

#### curl: Sign a PDF

```bash
curl -s -X POST http://localhost:8009/sign \
  -d '{"input_file":"testdata/test.pdf","output_file":"/tmp/signed.pdf"}'
```

#### curl: Sign with per-request overrides

```bash
curl -s -X POST http://localhost:8009/sign \
  -d '{
    "input_file": "testdata/mcx-SUN844.pdf",
    "output_file": "/tmp/mcx-signed.pdf",
    "reason": "Contract Note",
    "contact": "Zerodha",
    "location": "Bangalore"
  }'
```

#### curl: Sign + encrypt

```bash
curl -s -X POST http://localhost:8009/sign \
  -d '{
    "input_file": "testdata/test.pdf",
    "output_file": "/tmp/signed-encrypted.pdf",
    "password": "secret123"
  }'
```

#### curl: Sign with coordinate overrides

```bash
curl -s -X POST http://localhost:8009/sign \
  -d '{
    "input_file": "testdata/test.pdf",
    "output_file": "/tmp/signed-coords.pdf",
    "coordinates": {"x1": 10, "y1": 700, "x2": 200, "y2": 650}
  }'
```

### 4. CSV Batch

Create a pipe-delimited CSV file (`batch.csv`):

```
testdata/test.pdf|/tmp/out1.pdf
testdata/mcx-SUN844.pdf|/tmp/out2.pdf|secret123
```

Format: `input|output[|password]`

```bash
./flashsign -config config.ini batch.csv
```

### 5. Directory Batch

Place PDFs in an input directory. To encrypt, prefix the filename with `PASSWORD_`:

```
input/
  report.pdf              # signed only
  SECRET_contract.pdf     # signed + encrypted with "SECRET"
```

```bash
./flashsign -config config.ini input/ /tmp/output/
```

Output:

```
/tmp/output/
  report.pdf
  contract.pdf
```

## S3 Support

Set `s3_enabled=true` and `s3_region=ap-south-1` in `config.ini`. Then use `s3://` paths:

```bash
curl -s -X POST http://localhost:8009/sign \
  -d '{
    "input_file": "s3://bucket/input.pdf",
    "output_file": "s3://bucket/signed.pdf"
  }'
```

Uses default AWS credential chain (env vars, `~/.aws/credentials`, IAM role).

## Run Tests

```bash
go test ./... -v
```
