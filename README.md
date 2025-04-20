# 보안점검 서비스

보안점검을 위해 대상 IP에 대한 네트워크 스캔을 수행하고, SSH, RDP, HTTP, HTTPS와 같은 서비스의 접속 가능 여부를 점검하는 도구입니다. 접속 가능한 서비스에 대해서는 화면 캡처를 증적으로 생성합니다.

## 주요 기능

- **CIDR 표기법 지원**: 단일 IP, 호스트명 또는 CIDR 표기법(예: 192.168.1.0/24)으로 대상 지정 가능
- 입력된 대상 IP에 대한 Nmap 스캔 수행 (TCP SYN 스캔, 서비스 버전 감지, 상위 1000개 포트 대상, 빠른 옵션: `-sS -sV -T4 --top-ports 1000`)
- **모든 스캔된 포트에서 실행 중인 SSH, RDP, HTTP, HTTPS 서비스 감지 및 접속 확인** (비표준 포트 지원)
- 각 서비스 접속 가능 여부 확인 및 증적 생성 (SSH/RDP는 텍스트, HTTP/HTTPS는 PNG 스크린샷)
- 점검 결과에 대한 Markdown, HTML, CSV 형식의 보고서 자동 생성

## 시스템 요구사항

- Python 3.7 이상
- Nmap 보안 스캐너 (시스템 PATH에 설치 및 설정 필요)
- Chrome 또는 Firefox 브라우저 (웹 스크린샷용)
- 해당 브라우저의 웹드라이버 (시스템 PATH에 있거나 Selenium이 찾을 수 있는 위치에 설치 필요. Selenium 4.6.0 이상 버전은 Selenium Manager를 통해 자동으로 드라이버를 관리하려고 시도할 수 있습니다.)
- 필요한 Python 라이브러리 (requirements.txt 참조)

## 설치 방법

1. 저장소를 클론하거나 소스 코드를 다운로드합니다.

2. 필요한 Python 의존성 패키지를 설치합니다:

```bash
pip install -r requirements.txt
```

3. Nmap이 시스템에 설치되어 있는지 확인합니다:

```bash
# Debian/Ubuntu 기반 시스템
sudo apt-get install nmap

# Red Hat/CentOS 기반 시스템
sudo yum install nmap

# macOS (Homebrew 사용)
brew install nmap
```

4. Chrome 또는 Firefox 브라우저가 설치되어 있는지 확인하고, 해당 브라우저 버전과 호환되는 웹드라이버를 설치하여 시스템 PATH에 추가하거나 Selenium이 찾을 수 있도록 설정합니다. (참고: Selenium 4.6.0 이상 버전은 Selenium Manager를 통해 이 과정을 자동으로 처리하려고 시도합니다.)

## 사용 방법

1. 대상 IP 주소가 포함된 텍스트 파일을 생성합니다 (한 줄에 하나씩):

```
192.168.1.1
10.0.0.1
example.com
192.168.0.0/24  # CIDR 표기법 (이 경우 192.168.0.0 ~ 192.168.0.255까지 256개 IP 스캔)
172.16.10.0/28  # CIDR 표기법 (이 경우 172.16.10.0 ~ 172.16.10.15까지 16개 IP 스캔)
```

2. 스캐너를 실행합니다:

```bash
python security_scanner.py targets.txt
```

3. `result_YYYYMMDD_HHMMSS` 디렉토리에 생성된 보고서를 확인합니다:
   - `result_YYYYMMDD_HHMMSS.md` - Markdown 보고서
   - `result_YYYYMMDD_HHMMSS.html` - HTML 보고서
   - `result_YYYYMMDD_HHMMSS.csv` - CSV 보고서
   - `screenshots/` - 캡처된 모든 스크린샷이 포함된 디렉토리

## CSV 보고서 형식

CSV 보고서는 다음 열을 포함합니다:
- IP: 대상 IP 주소
- 응답: 호스트가 스캔에 응답했는지 여부 (Y/N)
- SSH: SSH 서비스가 열려 있는지 여부 (Y/N)
- SSH_포트: 감지된 SSH 포트 목록 (세미콜론으로 구분)
- RDP: RDP 서비스가 열려 있는지 여부 (Y/N)
- RDP_포트: 감지된 RDP 포트 목록 (세미콜론으로 구분)
- HTTP: HTTP 서비스가 열려 있는지 여부 (Y/N)
- HTTP_포트: 감지된 HTTP 포트 목록 (세미콜론으로 구분)
- HTTPS: HTTPS 서비스가 열려 있는지 여부 (Y/N)
- HTTPS_포트: 감지된 HTTPS 포트 목록 (세미콜론으로 구분)

## 증적 파일

- SSH: 연결 세부 정보가 포함된 텍스트 파일 (포트별로 생성)
- RDP: 연결 세부 정보가 포함된 텍스트 파일 (포트별로 생성)
- HTTP/HTTPS: 웹 페이지의 PNG 이미지 (포트별로 생성)

## 코드 설명

### 주요 클래스 및 함수

- `SecurityScanner`: 메인 스캐너 클래스
  - `__init__()`: 스캐너 초기화 (결과 디렉토리, Nmap, 웹드라이버 설정)
  - `parse_target()`: 단일 대상 문자열(IP, 호스트명, CIDR)을 IP 주소 목록으로 파싱
  - `read_targets()`: 대상 파일(`target_file`)을 읽어 전체 대상 IP 목록 생성
  - `scan_all_targets()`: 모든 대상에 대해 초기 Nmap 포트 스캔 수행 및 서비스 감지
  - `prepare_detailed_scan()`: 초기 스캔 결과를 상세 점검용 구조로 변환
  - `capture_ssh_screenshot()`: SSH 연결 시도 및 텍스트 증적 생성
  - `capture_rdp_screenshot()`: RDP 연결 시도 및 텍스트 증적 생성
  - `capture_web_screenshot()`: 웹 페이지 접속 및 스크린샷(PNG) 캡처
  - `check_services()`: 감지된 서비스 포트에 대해 `capture_*` 메서드 호출하여 상세 점검 수행
  - `generate_markdown_report()`: Markdown 형식 보고서 생성
  - `generate_html_report()`: HTML 형식 보고서 생성
  - `generate_csv_report()`: CSV 형식 보고서 생성
  - `run()`: 전체 스캔 워크플로우 실행 (대상 읽기 -> 초기 스캔 -> 상세 점검 -> 보고서 생성)

### 워크플로우

1. 대상 파일(`target_file`)에서 IP 주소, 호스트명, CIDR 표기법 읽기
2. CIDR 표기법을 개별 IP 주소로 확장하여 전체 대상 목록 생성
3. 모든 대상에 대해 초기 Nmap 스캔 수행 (`-sS -sV -T4 --top-ports 1000`)하여 응답 여부 및 열린 포트, 서비스 정보 확인
4. 스캔 결과 분석하여 각 대상별 SSH, RDP, HTTP, HTTPS 서비스 및 해당 포트 식별 (비표준 포트 포함)
5. 응답한 호스트에 대해서만 상세 점검 수행:
   - 식별된 각 서비스 포트에 대해 연결 시도 (SSH, RDP) 또는 웹 접속 (HTTP, HTTPS)
   - 연결/접속 성공 시 증적 생성 (SSH/RDP는 텍스트 파일, HTTP/HTTPS는 PNG 스크린샷)
6. 모든 대상(응답/비응답 포함)의 결과를 종합하여 Markdown, HTML, CSV 보고서 생성

## CIDR 표기법 지원

CIDR(Classless Inter-Domain Routing) 표기법을 사용하여 IP 범위를 지정할 수 있습니다:

- 예: `192.168.1.0/24`는 192.168.1.0부터 192.168.1.255까지의 256개 IP 주소를 의미합니다.
- 예: `10.0.0.0/28`은 10.0.0.0부터 10.0.0.15까지의 16개 IP 주소를 의미합니다.

스크립트는 Python의 `ipaddress` 모듈을 사용하여 CIDR 표기법을 처리합니다:

1. 입력 파일의 각 줄이 CIDR 표기법인지 확인
2. CIDR 표기법인 경우 해당 네트워크 내의 모든 IP 주소 생성
3. 생성된 모든 IP 주소를 대상 목록에 추가

**주의사항**: 너무 큰 네트워크 범위(예: /16 이상)를 지정하면 스캔 시간이 매우 오래 걸릴 수 있습니다. 스크립트는 네트워크 크기가 256개 이상인 경우 경고 메시지를 출력합니다.

## 비표준 포트 감지 방식

이 스크립트는 표준 포트뿐만 아니라 모든 포트에서 실행 중인 서비스를 감지할 수 있습니다:

1. **서비스 감지 방법**:
   - Nmap의 서비스 버전 감지(-sV) 옵션을 사용하여 각 포트에서 실행 중인 서비스 식별
   - 서비스 이름과 제품 정보를 분석하여 SSH, RDP, HTTP, HTTPS 서비스 감지
   - 비표준 포트에서 실행 중인 서비스도 자동으로 감지

2. **서비스별 특징 식별**:
   - SSH: 'ssh'라는 문자열이 서비스 이름에 포함된 포트
   - RDP: 'ms-wbt-server', 'rdp', 'remote desktop', 'msrdp' 등의 문자열이 서비스 이름이나 제품 정보에 포함된 포트
   - HTTP: 'http'라는 문자열이 포함되고, 'https', 'ssl', 'tls' 등의 보안 관련 문자열이 포함되지 않은 포트
   - HTTPS: 'https', 'ssl/http', 'http-over-ssl' 등의 문자열이 서비스 이름에 포함된 포트

3. **연결 테스트**:
   - 각 서비스의 모든 감지된 포트에 대해 개별적으로 연결 테스트 수행
   - 각 포트별로 별도의 증적 파일 생성

## 문제 해결

- 웹드라이버 문제가 발생하는 경우, Chrome 또는 Firefox가 시스템에 설치되어 있는지 확인하세요.
- 자세한 오류 정보는 `security_scan.log` 로그 파일을 확인하세요.
- SSH/RDP 연결 확인 시 실제로 로그인하지는 않으며, 연결 가능 여부만 확인합니다.
- 서비스 감지의 정확도는 Nmap의 결과에 의존합니다. 일부 서비스는 정확하게 감지되지 않을 수 있습니다.
- 대량의 IP 주소를 스캔할 때는 시스템 리소스와 네트워크 부하를 고려하세요.

## 커스터마이징

- `scan_all_targets` 메서드 내 `self.nm.scan()` 호출 시 Nmap 스캔 옵션(`arguments`)을 조정하여 스캔 매개변수를 변경할 수 있습니다.
- `scan_all_targets` 메서드 내 서비스 감지 로직을 수정하여 더 많은 서비스 유형을 지원하도록 확장할 수 있습니다.
- `__init__` 메서드 내 `self.driver.set_window_size(1920, 1080)` 부분을 수정하여 스크린샷 해상도를 변경할 수 있습니다.
- 스크립트 상단의 `logging.basicConfig` 설정을 변경하여 로깅 수준(`level`)이나 포맷(`format`)을 조정할 수 있습니다.
