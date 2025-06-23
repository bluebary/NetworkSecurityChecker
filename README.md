<<<<<<< HEAD
# 보안 스캐너 (Security Scanner)

지정된 대상에 대해 포트 스캔, 서비스 식별 및 기본적인 취약점 점검을 수행하는 Python 스크립트입니다. 스캔 결과는 Markdown, HTML, CSV 형식의 보고서로 생성됩니다.

## 주요 기능

*   **대상 지정**: 파일에서 IP 주소, 호스트명 또는 CIDR 표기법으로 스캔 대상을 읽습니다.
*   **포트 스캔**: `nmap`을 활용하여 일반적인 포트에 대한 TCP SYN 스캔 및 서비스 버전 감지를 수행합니다.
*   **서비스 식별**: SSH, RDP, HTTP, HTTPS, SMB, FTP 서비스의 실행 여부를 확인합니다.
*   **상세 점검**:
    *   SSH, RDP, SMB, FTP: 연결 시도 및 익명 접속 가능성 등을 확인하고 관련 정보를 텍스트 파일로 저장합니다.
    *   HTTP, HTTPS: 웹 페이지 스크린샷을 캡처하여 시각적인 정보를 제공합니다.
*   **보고서 생성**: 스캔 결과를 Markdown, HTML, CSV 형식으로 생성하여 가독성을 높입니다.
*   **로깅**: 스캔 진행 상황 및 오류를 `security_scan.log` 파일에 기록합니다.

## 요구 사항

실행 환경에 다음 라이브러리들이 설치되어 있어야 합니다:

*   `python-nmap`
*   `paramiko`
*   `requests`
*   `ipaddress` (Python 3.3+ 기본 내장)
*   `selenium`
*   `urllib3`
*   `pysmbclient` (SMB 스캔용)
*   `ftplib` (Python 기본 내장, FTP 스캔용)

또한, 시스템에 `nmap`이 설치되어 있어야 하며, 웹 스크린샷 기능을 사용하기 위해서는 `Chrome` 또는 `Firefox` 웹 브라우저와 해당 브라우저의 `WebDriver`가 설치되어 경로에 잡혀 있어야 합니다.

다음 명령어로 필요한 Python 라이브러리를 설치할 수 있습니다:
```bash
pip install -r requirements.txt
```
(`requirements.txt` 파일에 위 라이브러리 목록이 포함되어 있다고 가정합니다. 없다면 직접 설치해야 합니다.)

## 사용 방법

1.  **대상 파일 준비**:
    스캔할 대상 IP 주소, 호스트명 또는 CIDR(예: `192.168.1.0/24`) 목록을 포함하는 텍스트 파일을 생성합니다. 기본 파일명은 `target.txt`입니다. 각 항목은 한 줄에 하나씩 작성합니다.

    예시 (`target.txt`):
    ```
    192.168.0.1
    example.com
    10.0.0.0/24
    ```

2.  **스크립트 실행**:
    터미널에서 다음 명령어를 사용하여 스크립트를 실행합니다.

    ```bash
    python security_scanner.py [옵션]
    ```

    **옵션**:
    *   `--target-file <파일경로>` 또는 `-t <파일경로>`: 대상 목록이 포함된 파일 경로를 지정합니다. (기본값: `target.txt`)

    예시:
    ```bash
    python security_scanner.py -t my_targets.txt
    ```

## 결과물

스캔이 완료되면 현재 날짜와 시간으로 명명된 `result_YYYYMMDD_HHMMSS` 형식의 디렉토리가 생성됩니다. 이 디렉토리에는 다음 파일들이 포함됩니다:

*   `result_YYYYMMDD_HHMMSS.md`: Markdown 형식의 스캔 보고서
*   `result_YYYYMMDD_HHMMSS.html`: HTML 형식의 스캔 보고서
*   `result_YYYYMMDD_HHMMSS.csv`: CSV 형식의 스캔 보고서
*   `screenshots/`:
    *   HTTP/HTTPS 서비스의 스크린샷 이미지 파일 (`.png`)
    *   SSH/RDP/SMB/FTP 서비스 점검 결과 텍스트 파일 (`.txt`)

또한, 스크립트 실행 디렉토리에 `security_scan.log` 파일이 생성되어 스캔 과정의 로그를 기록합니다.
=======
# NetworkSecurityChecker (보안점검 서비스)

대상 IP/호스트/네트워크에 대해 Nmap 기반 포트 스캔, SSH/RDP/HTTP/HTTPS 서비스 감지 및 접속 가능성 점검, 증적(스크린샷/텍스트) 생성, Markdown/HTML/CSV 보고서 자동화 도구입니다.

---

## 주요 기능

- 단일 IP, 호스트명, CIDR 표기법(예: 192.168.1.0/24) 지원
- Nmap을 통한 빠른 포트 스캔 및 서비스 버전 감지
- 비표준 포트 포함 SSH, RDP, HTTP, HTTPS 서비스 자동 감지 및 접속 확인
- SSH/RDP는 텍스트 증적, HTTP/HTTPS는 PNG 스크린샷 생성
- Markdown, HTML, CSV 보고서 자동 생성
- 대량 IP 처리, 서비스별 상세 증적 파일 제공

---

## 설치 및 준비

1. **Python 3.7 이상** 필요
2. **Nmap** 설치 (시스템 PATH에 등록)
3. **Chrome/Firefox 브라우저** 설치
4. **필수 패키지 설치**
   ```bash
   pip install -r requirements.txt
   ```
   (필요시 `webdriver-manager`도 설치: `pip install webdriver-manager`)

5. **웹드라이버 자동 설치**
   - Selenium 4.6.0 이상은 자동으로 드라이버를 관리합니다.
   - 수동 설치가 필요하면 [ChromeDriver](https://chromedriver.chromium.org/downloads) 또는 [GeckoDriver](https://github.com/mozilla/geckodriver/releases) 다운로드 후 PATH에 추가.

6. **Nmap 설치 예시**
   - Windows: [nmap.org](https://nmap.org/download.html)에서 설치 후 환경변수 PATH에 추가
   - Ubuntu: `sudo apt-get install nmap`
   - macOS: `brew install nmap`

---

## 사용법

1. **대상 파일 작성**
   - `target.txt` 파일에 한 줄에 하나씩 IP, 호스트명, 또는 CIDR 입력
   ```
   192.168.1.1
   example.com
   10.0.0.0/28
   ```

2. **실행**
   ```bash
   python security_scanner.py --target-file target.txt
   ```
   또는 기본 파일명 사용 시
   ```bash
   python security_scanner.py
   ```

3. **결과 확인**
   - `result_YYYYMMDD_HHMMSS/` 폴더에 Markdown, HTML, CSV 보고서와 증적 파일 생성
>>>>>>> cd209ab (README.md에서 충돌 마커 제거 및 내용 정리)

## 주의 사항

*   이 스크립트는 대상 시스템에 대한 명시적인 허가를 받은 후에만 사용해야 합니다. 무단 스캔은 불법일 수 있습니다.
*   매우 큰 네트워크 범위 (예: `/16` 이상)를 스캔 대상으로 지정하면 시간이 매우 오래 걸릴 수 있습니다.
*   웹드라이버 설정에 문제가 있을 경우 웹 스크린샷 기능이 작동하지 않을 수 있습니다.
*   SMB/FTP 익명 접속 시도는 실제 환경 및 권한 설정에 따라 결과가 다를 수 있습니다.
<<<<<<< HEAD
=======

## 문의

- 문의: [bluebary@gmail.com]
>>>>>>> cd209ab (README.md에서 충돌 마커 제거 및 내용 정리)
