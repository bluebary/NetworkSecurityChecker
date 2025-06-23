# 보안 스캐너 (Security Scanner)
=======
# NetworkSecurityChecker (보안점검 서비스)

대상 IP/호스트/네트워크에 대해 Nmap 기반 포트 스캔, SSH/RDP/HTTP/HTTPS 서비스 감지 및 접속 가능성 점검, 증적(스크린샷/텍스트) 생성, Markdown/HTML/CSV 보고서 자동화 도구입니다.


## 주요 기능

- 단일 IP, 호스트명, CIDR 표기법(예: 192.168.1.0/24) 지원
- Nmap을 통한 빠른 포트 스캔 및 서비스 버전 감지
- 비표준 포트 포함 SSH, RDP, HTTP, HTTPS 서비스 자동 감지 및 접속 확인
- SSH/RDP는 텍스트 증적, HTTP/HTTPS는 PNG 스크린샷 생성
- Markdown, HTML, CSV 보고서 자동 생성
- 대량 IP 처리, 서비스별 상세 증적 파일 제공


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

**결과 확인**
   - `result_YYYYMMDD_HHMMSS/` 폴더에 Markdown, HTML, CSV 보고서와 증적 파일 생성


## 주의 사항

*   이 스크립트는 대상 시스템에 대한 명시적인 허가를 받은 후에만 사용해야 합니다. 무단 스캔은 불법일 수 있습니다.
*   매우 큰 네트워크 범위 (예: `/16` 이상)를 스캔 대상으로 지정하면 시간이 매우 오래 걸릴 수 있습니다.
*   웹드라이버 설정에 문제가 있을 경우 웹 스크린샷 기능이 작동하지 않을 수 있습니다.
*   SMB/FTP 익명 접속 시도는 실제 환경 및 권한 설정에 따라 결과가 다를 수 있습니다.


## 문의

- 문의: [bluebary@gmail.com]