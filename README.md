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

---

## 빌드(실행파일 생성)

- `improved_build_script.txt` 또는 `build_command.bat` 참고
- 예시:
  ```bat
  pyinstaller --onefile --add-data "requirements.txt;." --hidden-import=nmap --hidden-import=paramiko --hidden-import=requests --hidden-import=selenium --hidden-import=urllib3 --hidden-import=ipaddress security_scanner.py
  ```
- 빌드 후 `dist/security_scanner.exe` 실행 가능

---

## 주요 옵션 및 환경

- SSL 인증서 오류(예: handshake failed) 발생 시:
  - 크롬 옵션에 `--ignore-certificate-errors`, `--allow-insecure-localhost`가 이미 적용되어 있음
  - 크롬/크롬드라이버 버전 일치 필수
  - Windows 루트 인증서 최신 상태 유지 권장
  - 자체 서명/만료 인증서 대상은 무시하고 스크린샷 시도

- 로그 파일: `security_scan.log`에서 상세 오류 확인

---

## requirements.txt 예시

```
python-nmap>=0.7.1
paramiko>=2.7.2
requests>=2.25.1
selenium>=4.1.0
urllib3>=1.26.5
```

---

## 보고서 및 증적 파일

- Markdown/HTML/CSV 보고서 자동 생성
- SSH/RDP: 연결 세부 정보 텍스트 파일
- HTTP/HTTPS: PNG 스크린샷 및 오류시 텍스트 파일

---

## 문제 해결

- 크롬/드라이버 버전 불일치: [chrome://settings/help](chrome://settings/help)에서 버전 확인 후 드라이버 교체
- Nmap 미설치: 시스템 PATH에 등록 필요
- SSL handshake 오류: 크롬 옵션, 드라이버 버전, 루트 인증서 확인
- 대량 CIDR 입력 시 스캔 시간 증가 주의

---

## 문의

- 문의: [bluebary@gmail.com]
