#!/usr/bin/env python3
import argparse, csv, datetime, logging, os, socket, sys, time, nmap, paramiko, requests, ipaddress, ftplib
from typing import Dict, List, Optional, Union, Set, Any, Tuple
from smbclient import SambaClient as smbclient, SambaClientError as SmbClientError 

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException
from urllib3.exceptions import InsecureRequestWarning

# 안전하지 않은 HTTPS 요청에 대한 경고 무시
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_scan.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SecurityScanner:
    def __init__(self, target_file: str):
        """
        보안 스캐너 초기화
        
        Args:
            target_file: 대상 IP 주소가 포함된 파일 경로 (한 줄에 하나씩)
                         각 줄은 단일 IP, 호스트명 또는 CIDR 표기법(예: 192.168.1.0/24)일 수 있음
        """
        self.target_file = target_file
        self.targets = []
        self.scan_results = {} # 최종 상세 결과를 저장할 딕셔너리
        self.responsive_hosts = {}  # 초기 포트 스캔 결과를 저장할 딕셔너리
        self.current_date = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.result_dir = f"result_{self.current_date}"
        self.screenshot_dir = f"{self.result_dir}/screenshots"
        
        # 결과 디렉토리 생성
        os.makedirs(self.result_dir, exist_ok=True)
        os.makedirs(self.screenshot_dir, exist_ok=True)
        
        # nmap 스캐너 초기화
        self.nm = nmap.PortScanner()
        
        # 웹드라이버 초기화 (스크린샷 캡처용)
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--allow-insecure-localhost")
        
        # 웹드라이버 설정
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_window_size(1920, 1080)
            logger.info("Chrome 웹드라이버가 성공적으로 초기화되었습니다.")
        except Exception as e:
            logger.error(f"Chrome 웹드라이버 초기화 실패: {e}")
            logger.info("Firefox 웹드라이버로 대체합니다.")
            try:
                from selenium.webdriver.firefox.options import Options as FirefoxOptions
                firefox_options = FirefoxOptions()
                firefox_options.add_argument("--headless")
                self.driver = webdriver.Firefox(options=firefox_options)
                self.driver.set_window_size(1920, 1080)
                logger.info("Firefox 웹드라이버가 성공적으로 초기화되었습니다.")
            except Exception as e:
                logger.error(f"Firefox 웹드라이버 초기화 실패: {e}")
                logger.error("웹 스크린샷 기능을 사용할 수 없습니다.")
                self.driver = None
    
    # PyInstaller 패키징 시 리소스 경로 얻기
    def resource_path(relative_path):
        """ 리소스 파일의 절대 경로를 가져옵니다. """
        try:
            # PyInstaller는 임시 폴더 _MEIPASS에 번들을 생성합니다
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)
    
    def parse_target(self, target_str: str) -> List[str]:
        """
        타겟 문자열을 파싱하여 IP 주소 리스트를 반환합니다.
        CIDR 표기법이 사용된 경우 해당 범위의 모든 IP 주소를 생성합니다.
        
        Args:
            target_str: 대상 IP 주소 또는 CIDR 표기법
            
        Returns:
            IP 주소 목록
        """
        # 공백 제거
        target_str = target_str.strip()
        
        try:
            # CIDR 표기법인지 확인 (예: 192.168.1.0/24)
            if '/' in target_str:
                network = ipaddress.ip_network(target_str, strict=False)
                # 네트워크 크기가 너무 큰 경우 경고 (예: /16 이상)
                if network.num_addresses > 256:
                    logger.warning(f"매우 큰 네트워크가 지정되었습니다: {target_str} ({network.num_addresses}개 주소). 스캔에 시간이 오래 걸릴 수 있습니다.")
                # 모든 IP 주소를 문자열 목록으로 반환
                return [str(ip) for ip in network.hosts()]
            else:
                # 단일 IP 주소 또는 호스트명인 경우 그대로 반환
                return [target_str]
        except ValueError as e:
            logger.error(f"유효하지 않은 IP 주소 또는 CIDR 표기법: {target_str} - {e}")
            return []
    
    def read_targets(self) -> List[str]:
        """대상 IP 주소를 입력 파일에서 읽습니다. CIDR 표기법도 처리합니다."""
        try:
            with open(self.target_file, 'r', encoding='utf-8') as f:
                # 파일의 각 줄을 읽음
                lines = [line.strip() for line in f if line.strip()]
            
            # 모든 타겟 파싱
            all_targets = []
            for line in lines:
                ip_list = self.parse_target(line)
                all_targets.extend(ip_list)
            
            # 중복 제거 및 정렬
            self.targets = sorted(list(set(all_targets)))
            
            logger.info(f"{self.target_file}에서 {len(lines)}개의 입력을 읽어 {len(self.targets)}개의 대상 IP를 생성했습니다.")
            return self.targets
        except Exception as e:
            logger.error(f"대상 파일 읽기 오류: {e}")
            sys.exit(1)
    
    def scan_all_targets(self) -> Dict[str, Dict]:
        """
        모든 대상에 대해 초기 포트 스캔을 수행하여 서비스를 탐지합니다.
        
        Returns:
            대상 IP를 키로 하고 서비스 정보를 값으로 하는 딕셔너리
        """
        logger.info("모든 대상에 대해 포트 스캔 수행 중...")
        results = {}
        
        # 대상을 배치로 나누어 스캔 (대량 타겟 처리를 위해)
        batch_size = 50  # 한 번에 스캔할 최대 대상 수
        total_batches = (len(self.targets) + batch_size - 1) // batch_size
        
        for i in range(0, len(self.targets), batch_size):
            batch = self.targets[i:i+batch_size]
            
            logger.info(f"Batch {i//batch_size + 1}/{total_batches} 스캔 중: {len(batch)}개 대상")
            
            for target in batch:
                try:
                    # TCP SYN 스캔(-sS)을 빠른 타이밍(-T4)으로 수행
                    # 서비스 버전 감지(-sV) 추가
                    # 일반 포트(--top-ports 1000)를 스캔하여 빠른 결과 도출
                    logger.info(f"대상 스캔 중: {target}")
                    self.nm.scan(target, arguments='-sS -sV -T4 --top-ports 1000')

                    # 결과 구조 초기화
                    result = {
                        'ip': target,
                        'responsive': target in self.nm.all_hosts(),
                        'ssh': {'open': False, 'ports': []},
                        'rdp': {'open': False, 'ports': []},
                        'http': {'open': False, 'ports': []},
                        'https': {'open': False, 'ports': []},
                        'smb': {'open': False, 'ports': []}, # SMB 추가
                        'ftp': {'open': False, 'ports': []}  # FTP 추가
                    }
                    
                    # 대상이 실제로 스캔되었는지 확인
                    if not result['responsive']:
                        logger.warning(f"대상 {target}이(가) 응답하지 않았습니다.")
                        results[target] = result
                        continue
                    
                    # 스캔 결과 처리
                    host_data = self.nm[target]
                    
                    # TCP 포트만 확인
                    if 'tcp' not in host_data:
                        logger.warning(f"대상 {target}에서 열린 TCP 포트가 없습니다.")
                        results[target] = result
                        continue
                    
                    # 열린 각 포트의 서비스 확인
                    for port, port_data in host_data['tcp'].items():
                        if port_data['state'] == 'open':
                            service_name = port_data.get('name', '').lower()
                            product = port_data.get('product', '').lower()
                            
                            # SSH 서비스 확인
                            if 'ssh' in service_name:
                                result['ssh']['open'] = True
                                result['ssh']['ports'].append(port)
                                logger.info(f"{target}에서 포트 {port}에 SSH 서비스 감지됨")
                            
                            # RDP 서비스 확인
                            if any(keyword in service_name or keyword in product for keyword in 
                                ['ms-wbt-server', 'rdp', 'remote desktop', 'msrdp']):
                                result['rdp']['open'] = True
                                result['rdp']['ports'].append(port)
                                logger.info(f"{target}에서 포트 {port}에 RDP 서비스 감지됨")
                            
                            # HTTP 서비스 확인 (HTTPS 제외)
                            if 'http' in service_name and not any(secure in service_name for secure in 
                                                                ['https', 'ssl', 'tls']):
                                result['http']['open'] = True
                                result['http']['ports'].append(port)
                                logger.info(f"{target}에서 포트 {port}에 HTTP 서비스 감지됨")
                            
                            # HTTPS 서비스 확인
                            if any(keyword in service_name for keyword in ['https', 'ssl/http', 'http-over-ssl']):
                                result['https']['open'] = True
                                result['https']['ports'].append(port)
                                logger.info(f"{target}에서 포트 {port}에 HTTPS 서비스 감지됨")
                            
                            # SMB 서비스 확인 (포트 445 또는 서비스 이름)
                            if port == 445 or 'microsoft-ds' in service_name:
                                result['smb']['open'] = True
                                result['smb']['ports'].append(port)
                                logger.info(f"{target}에서 포트 {port}에 SMB 서비스 감지됨")

                            # FTP 서비스 확인
                            if 'ftp' in service_name:
                                result['ftp']['open'] = True
                                result['ftp']['ports'].append(port)
                                logger.info(f"{target}에서 포트 {port}에 FTP 서비스 감지됨")
                            
                            # HTTP/HTTPS 추가 확인 (제품 이름이나 버전 정보 사용)
                            if ('http' in product or 'web' in product or 'apache' in product or
                                'nginx' in product or 'iis' in product):
                                is_secure = any(secure in service_name or secure in product for secure in
                                                ['https', 'ssl', 'tls'])
                                
                                if is_secure:
                                    # 이미 HTTP 포트로 등록되지 않은 경우에만 HTTPS로 추가
                                    if port not in result['http']['ports']:
                                        result['https']['open'] = True
                                        if port not in result['https']['ports']:
                                            result['https']['ports'].append(port)
                                            logger.info(f"{target}에서 포트 {port}에 HTTPS 서비스 추가 감지됨 (제품 정보 기반)")
                                else:
                                    # 이미 HTTPS 포트로 등록되지 않은 경우에만 HTTP로 추가
                                    if port not in result['https']['ports']:
                                        result['http']['open'] = True
                                        if port not in result['http']['ports']:
                                            result['http']['ports'].append(port)
                                            logger.info(f"{target}에서 포트 {port}에 HTTP 서비스 추가 감지됨 (제품 정보 기반)")

                    # 일반적인 포트가 감지되지 않았을 때 기본 포트 확인
                    # 이미 발견된 포트가 없는 경우에만 기본 포트를 체크합니다
                    
                    # 표준 포트 확인 (포트 22의 SSH)
                    if 'tcp' in host_data and 22 in host_data['tcp'] and host_data['tcp'][22]['state'] == 'open' and not result['ssh']['ports']:
                        result['ssh']['open'] = True
                        result['ssh']['ports'].append(22)
                        logger.info(f"{target}에서 기본 포트 22에 SSH 서비스 감지됨 (서비스 이름 정보 없음)")
                    
                    # 표준 포트 확인 (포트 3389의 RDP)
                    if 'tcp' in host_data and 3389 in host_data['tcp'] and host_data['tcp'][3389]['state'] == 'open' and not result['rdp']['ports']:
                        result['rdp']['open'] = True
                        result['rdp']['ports'].append(3389)
                        logger.info(f"{target}에서 기본 포트 3389에 RDP 서비스 감지됨 (서비스 이름 정보 없음)")
                    
                    # 표준 포트 확인 (포트 80의 HTTP)
                    if 'tcp' in host_data and 80 in host_data['tcp'] and host_data['tcp'][80]['state'] == 'open' and not result['http']['ports']:
                        result['http']['open'] = True
                        result['http']['ports'].append(80)
                        logger.info(f"{target}에서 기본 포트 80에 HTTP 서비스 감지됨 (서비스 이름 정보 없음)")
                    
                    # 표준 포트 확인 (포트 443의 HTTPS)
                    if 'tcp' in host_data and 443 in host_data['tcp'] and host_data['tcp'][443]['state'] == 'open' and not result['https']['ports']:
                        result['https']['open'] = True
                        result['https']['ports'].append(443)
                        logger.info(f"{target}에서 기본 포트 443에 HTTPS 서비스 감지됨 (서비스 이름 정보 없음)")

                    # 표준 포트 확인 (포트 445의 SMB)
                    if 'tcp' in host_data and 445 in host_data['tcp'] and host_data['tcp'][445]['state'] == 'open' and not result['smb']['ports']:
                        result['smb']['open'] = True
                        result['smb']['ports'].append(445)
                        logger.info(f"{target}에서 기본 포트 445에 SMB 서비스 감지됨 (서비스 이름 정보 없음)")

                    # 표준 포트 확인 (포트 21의 FTP)
                    if 'tcp' in host_data and 21 in host_data['tcp'] and host_data['tcp'][21]['state'] == 'open' and not result['ftp']['ports']:
                        result['ftp']['open'] = True
                        result['ftp']['ports'].append(21)
                        logger.info(f"{target}에서 기본 포트 21에 FTP 서비스 감지됨 (서비스 이름 정보 없음)")
                    
                    # 모든 서비스의 포트 정렬
                    for service in ['ssh', 'rdp', 'http', 'https', 'smb', 'ftp']:
                        if service in result: # 서비스 키가 존재하는지 확인
                            result[service]['ports'] = sorted(list(set(result[service]['ports']))) # 중복 제거 및 정렬
                    
                    results[target] = result
                    
                except Exception as e:
                    logger.error(f"{target} 스캔 오류: {e}")
                    results[target] = {
                        'ip': target,
                        'responsive': False,
                        'ssh': {'open': False, 'ports': []},
                        'rdp': {'open': False, 'ports': []},
                        'http': {'open': False, 'ports': []},
                        'https': {'open': False, 'ports': []},
                        'smb': {'open': False, 'ports': []}, # SMB 추가
                        'ftp': {'open': False, 'ports': []}  # FTP 추가
                    }
        
        # 응답한 호스트 수 계산
        responsive_count = sum(1 for result in results.values() if result['responsive'])
        logger.info(f"총 {len(self.targets)}개 대상 중 {responsive_count}개 응답 호스트 발견")
        
        return results
    
    def prepare_detailed_scan(self, scan_info: Dict) -> Dict[str, Any]:
        """
        초기 포트 스캔 결과를 기반으로 상세 점검을 위한 결과 구조를 준비합니다.
        
        Args:
            scan_info: 초기 포트 스캔 결과
            
        Returns:
            스크린샷 필드가 추가된 결과 Dictionary
        """
        result = {
            'ip': scan_info['ip'],
            'responsive': scan_info['responsive'],
            'ssh': {
                'open': scan_info['ssh']['open'],
                'ports': scan_info['ssh']['ports'].copy(),
                'screenshots': {}
            },
            'rdp': {
                'open': scan_info['rdp']['open'],
                'ports': scan_info['rdp']['ports'].copy(),
                'screenshots': {}
            },
            'http': {
                'open': scan_info['http']['open'],
                'ports': scan_info['http']['ports'].copy(),
                'screenshots': {}
            },
            'https': {
                'open': scan_info['https']['open'],
                'ports': scan_info['https']['ports'].copy(),
                'screenshots': {}
            },
            'smb': { # SMB 추가
                'open': scan_info.get('smb', {}).get('open', False), # scan_info에 smb 키가 없을 경우 대비
                'ports': scan_info.get('smb', {}).get('ports', []).copy(),
                'screenshots': {}
            },
            'ftp': { # FTP 추가
                'open': scan_info.get('ftp', {}).get('open', False), # scan_info에 ftp 키가 없을 경우 대비
                'ports': scan_info.get('ftp', {}).get('ports', []).copy(),
                'screenshots': {}
            }
        }
        
        return result
    
    def capture_ssh_screenshot(self, target: str, ports: List[int]) -> Dict[int, str]:
        """
        SSH 연결 스크린샷 캡처 (여러 포트 지원)
        
        Args:
            target: SSH 서버의 IP 주소
            ports: 확인할 SSH 포트 목록
            
        Returns:
            포트별 스크린샷 파일 경로를 포함하는 Dictionary
        """
        screenshots = {}
        
        for port in ports:
            logger.info(f"{target}의 포트 {port}에 대한 SSH 스크린샷 캡처 시도 중")
            
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # 타임아웃과 함께 연결 시도
                client.connect(target, port=port, username='invaliduser', password='invalidpassword', timeout=5)
                
                # 예외 없이 이 위치에 도달하면 연결이 허용된 것(유효하지 않은 자격 증명으로는 불가능함)
                logger.warning(f"{target}의 포트 {port}에 대한 SSH 연결이 유효하지 않은 자격 증명을 수락했습니다!")
                client.close()
                
            except paramiko.AuthenticationException:
                # 이것은 실제로 "성공" - 서버가 존재하고 응답하지만 인증은 거부함
                logger.info(f"{target}의 포트 {port}에 대한 SSH 인증 실패 (예상된 동작)")
                
                # 연결 정보가 포함된 텍스트 파일을 "스크린샷"으로 생성
                screenshot_path = f"{self.screenshot_dir}/{target}_ssh_port_{port}.txt"
                with open(screenshot_path, 'w', encoding='utf-8') as f:
                    f.write(f"{target}의 포트 {port}에 대한 SSH 연결 확인됨\n")
                    f.write(f"타임스탬프: {datetime.datetime.now().isoformat()}\n")
                    f.write("테스트 자격 증명으로 인증 실패 (예상된 동작)\n")
                
                screenshots[port] = screenshot_path
                
            except (socket.error, paramiko.SSHException) as e:
                logger.error(f"{target}의 포트 {port}에 대한 SSH 연결 오류: {e}")
                
            except Exception as e:
                logger.error(f"{target}의 포트 {port}에 대한 SSH 스크린샷 캡처 중 예상치 못한 오류: {e}")
        
        return screenshots
    
    def capture_rdp_screenshot(self, target: str, ports: List[int]) -> Dict[int, str]:
        """
        RDP 연결성 확인 (여러 포트 지원)
        
        Args:
            target: RDP 서버의 IP 주소
            ports: 확인할 RDP 포트 목록
            
        Returns:
            포트별 스크린샷 파일 경로를 포함하는 Dictionary
        """
        screenshots = {}
        
        for port in ports:
            logger.info(f"{target}의 포트 {port}에 대한 RDP 연결성 확인 중")
            
            try:
                # RDP 포트가 응답하는지 확인하기 위한 간단한 소켓 연결
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((target, port))
                
                # RDP 서버는 프로토콜 핸드셰이크의 일부로 일부 데이터를 다시 보내야 함
                initial_data = s.recv(1024)
                s.close()
                
                if initial_data:
                    logger.info(f"{target}의 포트 {port}에서 RDP 서비스 응답 확인")
                    
                    # 연결 정보가 포함된 텍스트 파일을 "스크린샷"으로 생성
                    screenshot_path = f"{self.screenshot_dir}/{target}_rdp_port_{port}.txt"
                    with open(screenshot_path, 'w', encoding='utf-8') as f:
                        f.write(f"{target}의 포트 {port}에 대한 RDP 연결 확인됨\n")
                        f.write(f"타임스탬프: {datetime.datetime.now().isoformat()}\n")
                        f.write(f"초기 핸드셰이크에서 {len(initial_data)} 바이트 수신\n")
                    
                    screenshots[port] = screenshot_path
                else:
                    logger.warning(f"{target}의 포트 {port}의 RDP 서비스가 초기 데이터를 보내지 않았습니다")
                    
            except socket.error as e:
                logger.error(f"{target}의 포트 {port}에 대한 RDP 연결 오류: {e}")
                
            except Exception as e:
                logger.error(f"{target}의 포트 {port}에 대한 RDP 확인 중 예상치 못한 오류: {e}")
                
        return screenshots
    
    def capture_web_screenshot(self, target: str, ports: List[int], is_https: bool) -> Dict[int, str]:
        """
        웹 페이지 스크린샷 캡처 (여러 포트 지원)
        
        Args:
            target: 웹 서버의 IP 주소
            ports: 확인할 웹 서버 포트 목록
            is_https: HTTPS 프로토콜 사용 여부
            
        Returns:
            포트별 스크린샷 또는 오류 파일 경로를 포함하는 Dictionary
        """
        protocol = "https" if is_https else "http"
        screenshots = {}
        
        # 웹드라이버가 초기화되지 않은 경우
        if self.driver is None:
            logger.error("웹드라이버가 초기화되지 않았습니다. 웹 스크린샷을 캡처할 수 없습니다.")
            # 모든 포트에 대해 오류 파일 생성
            for port in ports:
                error_path = f"{self.screenshot_dir}/{target}_{protocol}_port_{port}_error.txt"
                with open(error_path, 'w', encoding='utf-8') as f:
                    f.write(f"{target}의 포트 {port}에 대한 {protocol.upper()} 접속 오류\n")
                    f.write(f"타임스탬프: {datetime.datetime.now().isoformat()}\n")
                    f.write("오류: 웹드라이버가 초기화되지 않았습니다.\n")
                screenshots[port] = error_path
            return screenshots
        
        for port in ports:
            url = f"{protocol}://{target}"
            
            # 표준 포트가 아닌 경우 포트 번호 추가
            if (is_https and port != 443) or (not is_https and port != 80):
                url = f"{url}:{port}"
                
            logger.info(f"{url}에 대한 스크린샷 캡처 중")
            
            try:
                # 먼저 requests를 사용하여 페이지에 접근 가능한지 확인
                response = requests.get(url, timeout=10, verify=False)
                
                if response.status_code < 400:  # 오류가 아닌 응답을 성공으로 간주
                    # Selenium을 사용하여 스크린샷 캡처
                    self.driver.get(url)
                    time.sleep(3)  # 페이지 로드 대기
                    
                    screenshot_path = f"{self.screenshot_dir}/{target}_{protocol}_port_{port}.png"
                    self.driver.save_screenshot(screenshot_path)
                    
                    logger.info(f"{url}에 대한 스크린샷이 {screenshot_path}에 저장되었습니다")
                    screenshots[port] = screenshot_path
                else:
                    logger.warning(f"{url}에 대해 상태 코드 {response.status_code} 수신")
                    # HTTP 에러 상태 코드를 파일로 저장
                    error_path = f"{self.screenshot_dir}/{target}_{protocol}_port_{port}_error.txt"
                    with open(error_path, 'w', encoding='utf-8') as f:
                        f.write(f"{target}의 포트 {port}에 대한 {protocol.upper()} 접속 오류\n")
                        f.write(f"타임스탬프: {datetime.datetime.now().isoformat()}\n")
                        f.write(f"URL: {url}\n")
                        f.write(f"상태 코드: {response.status_code}\n")
                        f.write(f"응답 메시지: {response.reason}\n")
                    screenshots[port] = error_path
                    
            except requests.RequestException as e:
                logger.error(f"{url}에 대한 요청 오류: {e}")
                # 연결 오류 정보를 파일로 저장
                error_path = f"{self.screenshot_dir}/{target}_{protocol}_port_{port}_error.txt"
                with open(error_path, 'w', encoding='utf-8') as f:
                    f.write(f"{target}의 포트 {port}에 대한 {protocol.upper()} 접속 오류\n")
                    f.write(f"타임스탬프: {datetime.datetime.now().isoformat()}\n")
                    f.write(f"URL: {url}\n")
                    f.write(f"오류 유형: {type(e).__name__}\n")
                    f.write(f"오류 메시지: {str(e)}\n")
                    
                    # 특정 오류 유형에 대한 추가 정보
                    if isinstance(e, requests.ConnectionError):
                        f.write("상세: 연결을 설정할 수 없습니다. 대상 호스트가 응답하지 않거나 포트가 닫혀 있습니다.\n")
                    elif isinstance(e, requests.Timeout):
                        f.write("상세: 연결 시간이 초과되었습니다. 네트워크 지연이 발생했거나 대상 시스템이 느리게 응답합니다.\n")
                    elif isinstance(e, requests.TooManyRedirects):
                        f.write("상세: 너무 많은 리다이렉션이 발생했습니다. 웹 서버 구성 문제일 수 있습니다.\n")
                    elif isinstance(e, requests.SSLError):
                        f.write("상세: SSL/TLS 인증서 검증에 실패했습니다. 인증서가 유효하지 않거나 자체 서명된 인증서일 수 있습니다.\n")
                        
                screenshots[port] = error_path
                
            except WebDriverException as e:
                logger.error(f"{url}에 대한 웹드라이버 오류: {e}")
                # 웹드라이버 오류 정보를 파일로 저장
                error_path = f"{self.screenshot_dir}/{target}_{protocol}_port_{port}_error.txt"
                with open(error_path, 'w', encoding='utf-8') as f:
                    f.write(f"{target}의 포트 {port}에 대한 {protocol.upper()} 접속 오류\n")
                    f.write(f"타임스탬프: {datetime.datetime.now().isoformat()}\n")
                    f.write(f"URL: {url}\n")
                    f.write(f"오류 유형: WebDriverException\n")
                    f.write(f"오류 메시지: {str(e)}\n")
                screenshots[port] = error_path
                
            except Exception as e:
                logger.error(f"{url}에 대한 스크린샷 캡처 중 예상치 못한 오류: {e}")
                # 예상치 못한 오류 정보를 파일로 저장
                error_path = f"{self.screenshot_dir}/{target}_{protocol}_port_{port}_error.txt"
                with open(error_path, 'w', encoding='utf-8') as f:
                    f.write(f"{target}의 포트 {port}에 대한 {protocol.upper()} 접속 오류\n")
                    f.write(f"타임스탬프: {datetime.datetime.now().isoformat()}\n")
                    f.write(f"URL: {url}\n")
                    f.write(f"오류 유형: {type(e).__name__}\n")
                    f.write(f"오류 메시지: {str(e)}\n")
                screenshots[port] = error_path
                
        return screenshots

    def capture_smb_screenshot(self, target: str, ports: List[int]) -> Dict[int, str]:
        """
        SMB 익명 접속을 시도하고 성공 시 공유 목록/파일 목록을 캡처합니다.

        Args:
            target: SMB 서버의 IP 주소
            ports: 확인할 SMB 포트 목록 (주로 445)

        Returns:
            포트별 익명 접속 결과 파일 경로를 포함하는 Dictionary
        """
        screenshots = {}
        if smbclient is None:
            logger.error("smbclient 라이브러리가 설치되지 않아 SMB 스캔을 건너<0xEB><0x9B><0x84>니다.")
            return screenshots

        for port in ports:
            logger.info(f"{target}의 포트 {port}에 대한 SMB 익명 접속 시도 중")
            screenshot_path = f"{self.screenshot_dir}/{target}_smb_port_{port}_anon_access.txt"
            
            try:
                # 익명 접속 시도 (사용자 이름과 비밀번호 없이)
                # smbclient.ClientConfig(username=None, password=None) # 명시적으로 None 설정 시도 (라이브러리 버전에 따라 필요할 수 있음)
                
                # 서버에 등록된 공유 목록 가져오기 시도
                shares = smbclient.listdir(f"//{target}", port=port, username=None, password=None)
                
                logger.info(f"{target}:{port} SMB 익명 접속 성공. 공유 목록 가져옴.")
                
                # 공유 목록 및 기본 파일 목록 저장
                with open(screenshot_path, 'w') as f:
                    f.write(f"SMB 익명 접속 성공 ({target}:{port})\n")
                    f.write(f"타임스탬프: {datetime.datetime.now().isoformat()}\n\n")
                    f.write("공유 목록:\n")
                    if shares:
                        for share in shares:
                            f.write(f"- {share}\n")
                            # 루트 디렉토리 파일 목록 가져오기 시도 (제한적일 수 있음)
                            try:
                                share_path = f"//{target}/{share}"
                                files = smbclient.listdir(share_path, port=port, username=None, password=None)
                                f.write(f"  \\_ 파일/디렉토리 ({len(files)}개):\n")
                                for item in files[:10]: # 너무 많을 경우 일부만 표시
                                    f.write(f"    - {item}\n")
                                if len(files) > 10:
                                    f.write("    - ... (더 많은 항목 존재)\n")
                            except SmbClientError as e:
                                f.write(f"  \\_ 공유 '{share}'의 파일 목록 가져오기 실패: {e}\n")
                            except Exception as e:
                                f.write(f"  \\_ 공유 '{share}'의 파일 목록 가져오기 중 예상치 못한 오류: {e}\n")
                    else:
                        f.write("- 공유 목록을 가져올 수 없거나 비어 있습니다.\n")
                
                screenshots[port] = screenshot_path
                
            except SmbClientError as e:
                # 일반적인 익명 접속 실패 오류 처리
                # 에러 코드나 메시지로 더 상세히 구분 가능 (예: 'NT_STATUS_ACCESS_DENIED')
                if "NT_STATUS_ACCESS_DENIED" in str(e) or "LOGON_FAILURE" in str(e):
                     logger.info(f"{target}:{port} SMB 익명 접속 실패 (예상된 동작): {e}")
                elif "NT_STATUS_CONNECTION_REFUSED" in str(e) or "Connection refused" in str(e):
                     logger.error(f"{target}:{port} SMB 연결 거부됨: {e}")
                elif "NT_STATUS_BAD_NETWORK_NAME" in str(e):
                     logger.error(f"{target}:{port} SMB 잘못된 네트워크 이름: {e}")
                else:
                     logger.error(f"{target}:{port} SMB 클라이언트 오류: {e}")
                     
            except socket.timeout:
                 logger.error(f"{target}:{port} SMB 연결 시간 초과")
            except OSError as e:
                 # 네트워크 관련 OS 오류 (예: "No route to host")
                 logger.error(f"{target}:{port} SMB OS 오류: {e}")
            except Exception as e:
                logger.error(f"{target}:{port} SMB 익명 접속 확인 중 예상치 못한 오류: {e}")
                
        return screenshots

    def capture_ftp_screenshot(self, target: str, ports: List[int]) -> Dict[int, str]:
        """
        FTP 익명 접속을 시도하고 성공 시 루트 디렉토리 목록을 캡처합니다.

        Args:
            target: FTP 서버의 IP 주소
            ports: 확인할 FTP 포트 목록 (주로 21)

        Returns:
            포트별 익명 접속 결과 파일 경로를 포함하는 Dictionary
        """
        screenshots = {}

        for port in ports:
            logger.info(f"{target}의 포트 {port}에 대한 FTP 익명 접속 시도 중")
            screenshot_path = f"{self.screenshot_dir}/{target}_ftp_port_{port}_anon_access.txt"
            
            try:
                # FTP 연결 시도 (타임아웃 설정)
                ftp = ftplib.FTP()
                ftp.connect(target, port, timeout=10)
                
                # 익명 로그인 시도
                ftp.login() # 사용자 'anonymous', 비밀번호 'anonymous@' 사용
                
                logger.info(f"{target}:{port} FTP 익명 접속 성공.")
                
                # 루트 디렉토리 목록 가져오기
                dir_listing = []
                try:
                    # NLST는 파일/디렉토리 이름 목록만 반환 (더 안정적일 수 있음)
                    dir_listing = ftp.nlst()
                    # 또는 상세 목록: dir_listing = ftp.retrlines('LIST') # 이 경우 콜백 함수 필요
                except ftplib.error_perm as e:
                    logger.warning(f"{target}:{port} FTP 디렉토리 목록 가져오기 실패 (권한 오류 가능성): {e}")
                    dir_listing.append(f"디렉토리 목록 가져오기 실패: {e}")
                except Exception as e:
                    logger.error(f"{target}:{port} FTP 디렉토리 목록 가져오기 중 오류: {e}")
                    dir_listing.append(f"디렉토리 목록 가져오기 중 오류: {e}")

                # 접속 성공 및 디렉토리 목록 저장
                with open(screenshot_path, 'w') as f:
                    f.write(f"FTP 익명 접속 성공 ({target}:{port})\n")
                    f.write(f"타임스탬프: {datetime.datetime.now().isoformat()}\n\n")
                    f.write("루트 디렉토리 목록:\n")
                    if dir_listing:
                        for item in dir_listing[:20]: # 너무 많을 경우 일부만 표시
                            f.write(f"- {item}\n")
                        if len(dir_listing) > 20:
                            f.write("- ... (더 많은 항목 존재)\n")
                    else:
                        f.write("- 디렉토리 목록을 가져올 수 없거나 비어 있습니다.\n")
                
                screenshots[port] = screenshot_path
                
                # 연결 종료
                ftp.quit()

            except ftplib.error_perm as e:
                # 로그인 실패 (530 Login incorrect 등)
                logger.info(f"{target}:{port} FTP 익명 접속 실패 (로그인 거부됨): {e}")
            except (socket.timeout, TimeoutError):
                logger.error(f"{target}:{port} FTP 연결 시간 초과")
            except (socket.error, ftplib.error_temp, ftplib.error_proto) as e:
                # 연결 거부, 프로토콜 오류 등
                logger.error(f"{target}:{port} FTP 연결 또는 프로토콜 오류: {e}")
            except Exception as e:
                logger.error(f"{target}:{port} FTP 익명 접속 확인 중 예상치 못한 오류: {e}")
            finally:
                # ftp 객체가 생성되었고 연결된 상태면 종료 시도
                if 'ftp' in locals() and ftp.sock:
                    try:
                        ftp.quit()
                    except Exception:
                        pass # 이미 오류가 발생했거나 연결이 끊겼을 수 있음

        return screenshots
        
    def check_services(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        서비스 접근성을 확인하고 스크린샷을 캡처합니다.
                
        Args:
            scan_result: 초기 포트 스캔 결과에서 생성된 상세 스캔 결과 구조
            scan_result: nmap 스캔 결과 딕셔너리
            
        Returns:
            스크린샷 경로로 업데이트된 스캔 결과 딕셔너리
        """
        target = scan_result['ip']
        logger.info(f"{target}에 대한 서비스 확인 중")
        
        # 호스트가 응답했는지 확인
        if not scan_result['responsive']:
            logger.info(f"{target}은(는) 응답하지 않는 호스트입니다. 서비스 확인을 건너뜁니다.")
            return scan_result
        
     
        # SSH 확인 (감지된 모든 포트)
        if scan_result['ssh']['open'] and scan_result['ssh']['ports']:
            scan_result['ssh']['screenshots'] = self.capture_ssh_screenshot(target, scan_result['ssh']['ports'])
        
        # RDP 확인 (감지된 모든 포트)
        if scan_result['rdp']['open'] and scan_result['rdp']['ports']:
            scan_result['rdp']['screenshots'] = self.capture_rdp_screenshot(target, scan_result['rdp']['ports'])
        
        # HTTP 확인 (감지된 모든 포트)
        if scan_result['http']['open'] and scan_result['http']['ports']:
            scan_result['http']['screenshots'] = self.capture_web_screenshot(target, scan_result['http']['ports'], False)
        
        # HTTPS 확인 (감지된 모든 포트)
        if scan_result['https']['open'] and scan_result['https']['ports']:
            scan_result['https']['screenshots'] = self.capture_web_screenshot(target, scan_result['https']['ports'], True)

        # SMB 확인 (감지된 모든 포트)
        if scan_result['smb']['open'] and scan_result['smb']['ports']:
             scan_result['smb']['screenshots'] = self.capture_smb_screenshot(target, scan_result['smb']['ports'])

        # FTP 확인 (감지된 모든 포트)
        if scan_result['ftp']['open'] and scan_result['ftp']['ports']:
             scan_result['ftp']['screenshots'] = self.capture_ftp_screenshot(target, scan_result['ftp']['ports'])
        
        return scan_result
    
    def generate_markdown_report(self) -> str:
        """스캔 결과의 Markdown 보고서를 생성합니다."""
        report_path = f"{self.result_dir}/result_{self.current_date}.md"
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"# 보안 스캔 보고서\n\n")
            f.write(f"**날짜:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## 요약\n\n")
            responsive_count = sum(1 for result in self.scan_results.values() if result.get('responsive', False))
            f.write(f"스캔된 총 대상: {len(self.scan_results)}\n")
            f.write(f"응답 호스트: {responsive_count}\n\n")
            
            f.write("| IP 주소 | 응답 | SSH | RDP | HTTP | HTTPS | SMB | FTP |\n") # SMB, FTP 추가
            f.write("|------------|------|-----|-----|------|-------|-----|-----|\n") # SMB, FTP 추가
            
            for target, result in self.scan_results.items():
                # 응답 상태 표시
                responsive_status = "✅" if result.get('responsive', False) else "❌"
                
                # 서비스 포트 정보 포맷팅 (비응답 호스트는 항상 닫힘)
                if not result.get('responsive', False):
                    ssh_status = rdp_status = http_status = https_status = "❌"
                else:
                    ssh_status = f"✅ ({', '.join(map(str, result['ssh']['ports']))})" if result['ssh']['open'] else "❌"
                    rdp_status = f"✅ ({', '.join(map(str, result['rdp']['ports']))})" if result['rdp']['open'] else "❌"
                    http_status = f"✅ ({', '.join(map(str, result['http']['ports']))})" if result['http']['open'] else "❌"
                    https_status = f"✅ ({', '.join(map(str, result['https']['ports']))})" if result['https']['open'] else "❌"
                    smb_status = f"✅ ({', '.join(map(str, result['smb']['ports']))})" if result['smb']['open'] else "❌" # SMB 추가
                    ftp_status = f"✅ ({', '.join(map(str, result['ftp']['ports']))})" if result['ftp']['open'] else "❌" # FTP 추가
                
                f.write(f"| {target} | {responsive_status} | {ssh_status} | {rdp_status} | {http_status} | {https_status} | {smb_status} | {ftp_status} |\n") # SMB, FTP 추가
            
            f.write("\n## 상세 결과\n\n")
            
            for target, result in self.scan_results.items():
                f.write(f"### {target}\n\n")
                
                # 비응답 호스트 처리
                if not result.get('responsive', False):
                    f.write("상태: **비응답**\n\n")
                    f.write("이 호스트는 포트 스캔에 응답하지 않았습니다. 상세 서비스 점검이 수행되지 않았습니다.\n\n")
                    f.write("\n---\n\n")
                    continue
                
                # SSH
                f.write("#### SSH 서비스\n\n")
                if result['ssh']['open']:
                    ssh_ports = ", ".join(map(str, result['ssh']['ports']))
                    f.write(f"상태: **열림** (포트: {ssh_ports})\n\n")
                    
                    # 각 SSH 포트에 대한 연결 세부 정보 링크
                    for port, screenshot_path in result['ssh']['screenshots'].items():
                        if screenshot_path:
                            rel_path = os.path.relpath(screenshot_path, self.result_dir)
                            f.write(f"[포트 {port}의 SSH 연결 세부 정보]({rel_path})\n\n")
                else:
                    f.write("상태: **닫힘**\n\n")
                
                # RDP
                f.write("#### RDP 서비스\n\n")
                if result['rdp']['open']:
                    rdp_ports = ", ".join(map(str, result['rdp']['ports']))
                    f.write(f"상태: **열림** (포트: {rdp_ports})\n\n")
                    
                    # 각 RDP 포트에 대한 연결 세부 정보 링크
                    for port, screenshot_path in result['rdp']['screenshots'].items():
                        if screenshot_path:
                            rel_path = os.path.relpath(screenshot_path, self.result_dir)
                            f.write(f"[포트 {port}의 RDP 연결 세부 정보]({rel_path})\n\n")
                else:
                    f.write("상태: **닫힘**\n\n")
                
                # HTTP
                f.write("#### HTTP 서비스\n\n")
                if result['http']['open']:
                    http_ports = ", ".join(map(str, result['http']['ports']))
                    f.write(f"상태: **열림** (포트: {http_ports})\n\n")
                    
                    # 각 HTTP 포트에 대한 결과 처리 (스크린샷 또는 오류)
                    for port, file_path in result['http']['screenshots'].items():
                        if file_path:
                            rel_path = os.path.relpath(file_path, self.result_dir)
                            if file_path.endswith('.png'):
                                # 스크린샷 처리
                                f.write(f"**포트 {port}의 HTTP 스크린샷:**\n\n")
                                f.write(f"![HTTP 포트 {port} 스크린샷]({rel_path})\n\n")
                            elif file_path.endswith('_error.txt'):
                                # 오류 메시지 처리
                                f.write(f"**포트 {port}의 HTTP 연결 오류:**\n\n")
                                try:
                                    with open(file_path, 'r', encoding='utf-8') as error_file:
                                        error_content = error_file.read()
                                    f.write(f"```\n{error_content}```\n\n")
                                except Exception as e:
                                    f.write(f"오류 파일을 읽을 수 없습니다: {e}\n\n")
                else:
                    f.write("상태: **닫힘**\n\n")
                
                # HTTPS
                f.write("#### HTTPS 서비스\n\n")
                if result['https']['open']:
                    https_ports = ", ".join(map(str, result['https']['ports']))
                    f.write(f"상태: **열림** (포트: {https_ports})\n\n")
                    
                    # 각 HTTPS 포트에 대한 결과 처리 (스크린샷 또는 오류)
                    for port, file_path in result['https']['screenshots'].items():
                        if file_path:
                            rel_path = os.path.relpath(file_path, self.result_dir)
                            if file_path.endswith('.png'):
                                # 스크린샷 처리
                                f.write(f"**포트 {port}의 HTTPS 스크린샷:**\n\n")
                                f.write(f"![HTTPS 포트 {port} 스크린샷]({rel_path})\n\n")
                            elif file_path.endswith('_error.txt'):
                                # 오류 메시지 처리
                                f.write(f"**포트 {port}의 HTTPS 연결 오류:**\n\n")
                                try:
                                    with open(file_path, 'r', encoding='utf-8') as error_file:
                                        error_content = error_file.read()
                                    f.write(f"```\n{error_content}```\n\n")
                                except Exception as e:
                                    f.write(f"오류 파일을 읽을 수 없습니다: {e}\n\n")
                else:
                    f.write("상태: **닫힘**\n\n")

                # SMB
                f.write("#### SMB 서비스\n\n")
                if result['smb']['open']:
                    smb_ports = ", ".join(map(str, result['smb']['ports']))
                    f.write(f"상태: **열림** (포트: {smb_ports})\n\n")
                    
                    # 각 SMB 포트에 대한 익명 접속 결과 링크
                    for port, screenshot_path in result['smb']['screenshots'].items():
                        if screenshot_path:
                            rel_path = os.path.relpath(screenshot_path, self.result_dir)
                            f.write(f"[포트 {port}의 SMB 익명 접속 결과]({rel_path})\n\n")
                else:
                    f.write("상태: **닫힘**\n\n")

                # FTP
                f.write("#### FTP 서비스\n\n")
                if result['ftp']['open']:
                    ftp_ports = ", ".join(map(str, result['ftp']['ports']))
                    f.write(f"상태: **열림** (포트: {ftp_ports})\n\n")
                    
                    # 각 FTP 포트에 대한 익명 접속 결과 링크
                    for port, screenshot_path in result['ftp']['screenshots'].items():
                        if screenshot_path:
                            rel_path = os.path.relpath(screenshot_path, self.result_dir)
                            f.write(f"[포트 {port}의 FTP 익명 접속 결과]({rel_path})\n\n")
                else:
                    f.write("상태: **닫힘**\n\n")
                
                f.write("\n---\n\n")
        
        logger.info(f"Markdown 보고서가 {report_path}에 생성되었습니다")
        return report_path
    
    def generate_html_report(self) -> str:
        """스캔 결과의 HTML 보고서를 생성합니다."""
        report_path = f"{self.result_dir}/result_{self.current_date}.html"
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("""
            <!DOCTYPE html>
            <html lang="ko">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>보안 스캔 보고서</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        margin: 0;
                        padding: 20px;
                        color: #333;
                    }
                    h1, h2, h3, h4, h5 {
                        color: #2c3e50;
                    }
                    table {
                        border-collapse: collapse;
                        width: 100%;
                        margin-bottom: 20px;
                    }
                    th, td {
                        border: 1px solid #ddd;
                        padding: 8px;
                        text-align: left;
                    }
                    th {
                        background-color: #f2f2f2;
                    }
                    tr:nth-child(even) {
                        background-color: #f9f9f9;
                    }
                    .status-open {
                        color: green;
                        font-weight: bold;
                    }
                    .status-closed {
                        color: red;
                    }
                    .status-error {
                        color: orange;
                        font-weight: bold;
                    }
                    .status-nonresponsive {
                        color: gray;
                        font-style: italic;
                    }
                    img {
                        max-width: 100%;
                        border: 1px solid #ddd;
                        margin: 10px 0;
                    }
                    .target-section {
                        margin-bottom: 30px;
                        border: 1px solid #eee;
                        padding: 15px;
                        border-radius: 5px;
                    }
                    .port-info {
                        color: #555;
                        font-style: italic;
                    }
                    .service-detail {
                        margin: 10px 0 20px 20px;
                        padding: 10px;
                        border-left: 3px solid #eee;
                    }
                    .error-detail {
                        background-color: #fff3f3;
                        border-left: 3px solid #ffcccc;
                        padding: 10px;
                        margin: 10px 0;
                        white-space: pre-wrap;
                        font-family: monospace;
                    }
                </style>
            </head>
            <body>
                <h1>보안 스캔 보고서</h1>
                <p><strong>날짜:</strong> """ + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
                
                <h2>요약</h2>
            """)
            
            responsive_count = sum(1 for result in self.scan_results.values() if result.get('responsive', False))
            f.write(f"""
                <p><strong>총 스캔 대상:</strong> {len(self.scan_results)}</p>
                <p><strong>응답 호스트:</strong> {responsive_count}</p>
                
                <table>
                    <tr>
                        <th>IP 주소</th>
                        <th>응답</th>
                        <th>SSH</th>
                        <th>RDP</th>
                        <th>HTTP</th>
                        <th>HTTPS</th>
                        <th>SMB</th> <!-- SMB 추가 -->
                        <th>FTP</th> <!-- FTP 추가 -->
                    </tr>
            """)
            
            for target, result in self.scan_results.items():
                # 응답 상태 표시
                responsive_status = "✅" if result.get('responsive', False) else "❌"
                
                # 서비스 포트 정보 포맷팅 (비응답 호스트는 항상 닫힘)
                if not result.get('responsive', False):
                    ssh_status = rdp_status = http_status = https_status = "❌"
                else:
                    ssh_status = f"✅ (포트: {', '.join(map(str, result['ssh']['ports']))})" if result['ssh']['open'] else "❌"
                    rdp_status = f"✅ (포트: {', '.join(map(str, result['rdp']['ports']))})" if result['rdp']['open'] else "❌"
                    http_status = f"✅ (포트: {', '.join(map(str, result['http']['ports']))})" if result['http']['open'] else "❌"
                    https_status = f"✅ (포트: {', '.join(map(str, result['https']['ports']))})" if result['https']['open'] else "❌"
                    smb_status = f"✅ (포트: {', '.join(map(str, result['smb']['ports']))})" if result['smb']['open'] else "❌" # SMB 추가
                    ftp_status = f"✅ (포트: {', '.join(map(str, result['ftp']['ports']))})" if result['ftp']['open'] else "❌" # FTP 추가
                
                f.write(f"""
                    <tr>
                        <td>{target}</td>
                        <td>{responsive_status}</td>
                        <td>{ssh_status}</td>
                        <td>{rdp_status}</td>
                        <td>{http_status}</td>
                        <td>{https_status}</td>
                        <td>{smb_status}</td> <!-- SMB 추가 -->
                        <td>{ftp_status}</td> <!-- FTP 추가 -->
                    </tr>
                """)
            
            f.write("""
                </table>
                
                <h2>상세 결과</h2>
            """)
            
            for target, result in self.scan_results.items():
                f.write(f"""
                <div class="target-section">
                    <h3>{target}</h3>
                """)
                
                # 비응답 호스트 처리
                if not result.get('responsive', False):
                    f.write("""
                    <p class="status-nonresponsive">상태: 비응답</p>
                    <p>이 호스트는 포트 스캔에 응답하지 않았습니다. 상세 서비스 점검이 수행되지 않았습니다.</p>
                    </div>
                    """)
                    continue
                
                # SSH
                f.write("""
                    <h4>SSH 서비스</h4>
                """)
                
                if result['ssh']['open']:
                    ssh_ports = ", ".join(map(str, result['ssh']['ports']))
                    f.write(f"""
                    <p class="status-open">상태: 열림 <span class="port-info">(포트: {ssh_ports})</span></p>
                    """)
                    
                    # 각 SSH 포트에 대한 연결 세부 정보
                    for port, screenshot_path in result['ssh']['screenshots'].items():
                        if screenshot_path:
                            with open(screenshot_path, 'r', encoding='utf-8') as ssh_file:
                                ssh_details = ssh_file.read()
                            f.write(f"""
                            <div class="service-detail">
                                <h5>포트 {port}의 SSH 연결 세부 정보</h5>
                                <pre>{ssh_details}</pre>
                            </div>
                            """)
                else:
                    f.write("""
                    <p class="status-closed">상태: 닫힘</p>
                    """)
                
                f.write("""
                    <h4>RDP 서비스</h4>
                """)
                
                if result['rdp']['open']:
                    rdp_ports = ", ".join(map(str, result['rdp']['ports']))
                    f.write(f"""
                    <p class="status-open">상태: 열림 <span class="port-info">(포트: {rdp_ports})</span></p>
                    """)
                    
                    # 각 RDP 포트에 대한 연결 세부 정보
                    for port, screenshot_path in result['rdp']['screenshots'].items():
                        if screenshot_path:
                            with open(screenshot_path, 'r', encoding='utf-8') as rdp_file:
                                rdp_details = rdp_file.read()
                            f.write(f"""
                            <div class="service-detail">
                                <h5>포트 {port}의 RDP 연결 세부 정보</h5>
                                <pre>{rdp_details}</pre>
                            </div>
                            """)
                else:
                    f.write("""
                    <p class="status-closed">상태: 닫힘</p>
                    """)
                
                f.write("""
                    <h4>HTTP 서비스</h4>
                """)
                
                if result['http']['open']:
                    http_ports = ", ".join(map(str, result['http']['ports']))
                    f.write(f"""
                    <p class="status-open">상태: 열림 <span class="port-info">(포트: {http_ports})</span></p>
                    """)
                    
                    # 각 HTTP 포트에 대한 결과 처리 (스크린샷 또는 오류)
                    for port, file_path in result['http']['screenshots'].items():
                        if file_path:
                            rel_path = os.path.relpath(file_path, self.result_dir)
                            if file_path.endswith('.png'):
                                # 스크린샷 처리
                                f.write(f"""
                                <div class="service-detail">
                                    <h5>포트 {port}의 HTTP 스크린샷</h5>
                                    <img src="{rel_path}" alt="HTTP 포트 {port} 스크린샷">
                                </div>
                                """)
                            elif file_path.endswith('_error.txt'):
                                # 오류 메시지 처리
                                f.write(f"""
                                <div class="service-detail">
                                    <h5 class="status-error">포트 {port}의 HTTP 연결 오류</h5>
                                """)
                                try:
                                    with open(file_path, 'r', encoding='utf-8') as error_file:
                                        error_content = error_file.read()
                                    f.write(f"""
                                    <div class="error-detail">{error_content}</div>
                                    """)
                                except Exception as e:
                                    f.write(f"""
                                    <div class="error-detail">오류 파일을 읽을 수 없습니다: {e}</div>
                                    """)
                                f.write("</div>")
                else:
                    f.write("""
                    <p class="status-closed">상태: 닫힘</p>
                    """)
                
                f.write("""
                    <h4>HTTPS 서비스</h4>
                """)
                
                if result['https']['open']:
                    https_ports = ", ".join(map(str, result['https']['ports']))
                    f.write(f"""
                    <p class="status-open">상태: 열림 <span class="port-info">(포트: {https_ports})</span></p>
                    """)
                    
                    # 각 HTTPS 포트에 대한 결과 처리 (스크린샷 또는 오류)
                    for port, file_path in result['https']['screenshots'].items():
                        if file_path:
                            rel_path = os.path.relpath(file_path, self.result_dir)
                            if file_path.endswith('.png'):
                                # 스크린샷 처리
                                f.write(f"""
                                <div class="service-detail">
                                    <h5>포트 {port}의 HTTPS 스크린샷</h5>
                                    <img src="{rel_path}" alt="HTTPS 포트 {port} 스크린샷">
                                </div>
                                """)
                            elif file_path.endswith('_error.txt'):
                                # 오류 메시지 처리
                                f.write(f"""
                                <div class="service-detail">
                                    <h5 class="status-error">포트 {port}의 HTTPS 연결 오류</h5>
                                """)
                                try:
                                    with open(file_path, 'r', encoding='utf-8') as error_file:
                                        error_content = error_file.read()
                                    f.write(f"""
                                    <div class="error-detail">{error_content}</div>
                                    """)
                                except Exception as e:
                                    f.write(f"""
                                    <div class="error-detail">오류 파일을 읽을 수 없습니다: {e}</div>
                                    """)
                                f.write("</div>")
                else:
                    f.write("""
                    <p class="status-closed">상태: 닫힘</p>
                    """)

                # SMB
                f.write("""
                    <h4>SMB 서비스</h4>
                """)
                if result['smb']['open']:
                    smb_ports = ", ".join(map(str, result['smb']['ports']))
                    f.write(f"""
                    <p class="status-open">상태: 열림 <span class="port-info">(포트: {smb_ports})</span></p>
                    """)
                    # 각 SMB 포트에 대한 익명 접속 결과
                    for port, screenshot_path in result['smb']['screenshots'].items():
                        if screenshot_path:
                            try:
                                with open(screenshot_path, 'r') as smb_file:
                                    smb_details = smb_file.read()
                                f.write(f"""
                                <div class="service-detail">
                                    <h5>포트 {port}의 SMB 익명 접속 결과</h5>
                                    <pre>{smb_details}</pre>
                                </div>
                                """)
                            except FileNotFoundError:
                                f.write(f"""
                                <div class="service-detail">
                                    <h5>포트 {port}의 SMB 익명 접속 결과</h5>
                                    <p>결과 파일을 찾을 수 없습니다: {os.path.basename(screenshot_path)}</p>
                                </div>
                                """)
                            except Exception as e:
                                f.write(f"""
                                <div class="service-detail">
                                    <h5>포트 {port}의 SMB 익명 접속 결과</h5>
                                    <p>결과 파일을 읽는 중 오류 발생: {e}</p>
                                </div>
                                """)
                else:
                    f.write("""
                    <p class="status-closed">상태: 닫힘</p>
                    """)

                # FTP
                f.write("""
                    <h4>FTP 서비스</h4>
                """)
                if result['ftp']['open']:
                    ftp_ports = ", ".join(map(str, result['ftp']['ports']))
                    f.write(f"""
                    <p class="status-open">상태: 열림 <span class="port-info">(포트: {ftp_ports})</span></p>
                    """)
                    # 각 FTP 포트에 대한 익명 접속 결과
                    for port, screenshot_path in result['ftp']['screenshots'].items():
                        if screenshot_path:
                            try:
                                with open(screenshot_path, 'r') as ftp_file:
                                    ftp_details = ftp_file.read()
                                f.write(f"""
                                <div class="service-detail">
                                    <h5>포트 {port}의 FTP 익명 접속 결과</h5>
                                    <pre>{ftp_details}</pre>
                                </div>
                                """)
                            except FileNotFoundError:
                                f.write(f"""
                                <div class="service-detail">
                                    <h5>포트 {port}의 FTP 익명 접속 결과</h5>
                                    <p>결과 파일을 찾을 수 없습니다: {os.path.basename(screenshot_path)}</p>
                                </div>
                                """)
                            except Exception as e:
                                f.write(f"""
                                <div class="service-detail">
                                    <h5>포트 {port}의 FTP 익명 접속 결과</h5>
                                    <p>결과 파일을 읽는 중 오류 발생: {e}</p>
                                </div>
                                """)
                else:
                    f.write("""
                    <p class="status-closed">상태: 닫힘</p>
                    """)

                f.write("""
                </div>
                """)
            
            f.write("""
            </body>
            </html>
            """)
        
        logger.info(f"HTML 보고서가 {report_path}에 생성되었습니다")
        return report_path
    
    def generate_csv_report(self) -> str:
        """스캔 결과의 CSV 보고서를 생성합니다."""
        report_path = f"{self.result_dir}/result_{self.current_date}.csv"
        
        with open(report_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', '응답', 'SSH', 'SSH_포트', 'RDP', 'RDP_포트', 'HTTP', 'HTTP_포트', 'HTTP_오류', 'HTTPS', 'HTTPS_포트', 'HTTPS_오류'])
            # CSV 헤더에 SMB, FTP 추가
            writer.writerow(['IP', '응답', 'SSH', 'SSH_포트', 'RDP', 'RDP_포트', 'HTTP', 'HTTP_포트', 'HTTPS', 'HTTPS_포트', 'SMB', 'SMB_포트', 'FTP', 'FTP_포트'])
            
            for target, result in self.scan_results.items():
                responsive_status = "Y" if result.get('responsive', False) else "N"
                
                if not result.get('responsive', False):
                    # 비응답 호스트는 모든 서비스가 닫힘
                    writer.writerow([target, responsive_status, "N", "", "N", "", "N", "", "", "N", "", ""])
                    # 비응답 호스트는 모든 서비스가 닫힘 (SMB, FTP 포함)
                    writer.writerow([target, responsive_status, "N", "", "N", "", "N", "", "N", "", "N", "", "N", ""])
                    continue
                
                ssh_status = "Y" if result['ssh']['open'] else "N"
                ssh_ports = ";".join(map(str, result['ssh']['ports'])) if result['ssh']['ports'] else ""
                
                rdp_status = "Y" if result['rdp']['open'] else "N"
                rdp_ports = ";".join(map(str, result['rdp']['ports'])) if result['rdp']['ports'] else ""
                
                http_status = "Y" if result['http']['open'] else "N"
                http_ports = ";".join(map(str, result['http']['ports'])) if result['http']['ports'] else ""
                http_errors = []
                for port, file_path in result['http']['screenshots'].items():
                    if file_path and file_path.endswith('_error.txt'):
                        try:
                            with open(file_path, 'r', encoding='utf-8') as error_file:
                                error_lines = error_file.readlines()
                                # 오류 유형과 메시지만 추출
                                error_type = ""
                                error_msg = ""
                                for line in error_lines:
                                    if line.startswith("오류 유형:"):
                                        error_type = line.split(":", 1)[1].strip()
                                    elif line.startswith("오류 메시지:"):
                                        error_msg = line.split(":", 1)[1].strip()
                                if error_type or error_msg:
                                    http_errors.append(f"Port {port}: {error_type} - {error_msg}")
                        except Exception:
                            http_errors.append(f"Port {port}: 오류 파일 읽기 실패")
                http_error_str = "; ".join(http_errors) if http_errors else ""
                
                https_status = "Y" if result['https']['open'] else "N"
                https_ports = ";".join(map(str, result['https']['ports'])) if result['https']['ports'] else ""
                https_errors = []
                for port, file_path in result['https']['screenshots'].items():
                    if file_path and file_path.endswith('_error.txt'):
                        try:
                            with open(file_path, 'r', encoding='utf-8') as error_file:
                                error_lines = error_file.readlines()
                                # 오류 유형과 메시지만 추출
                                error_type = ""
                                error_msg = ""
                                for line in error_lines:
                                    if line.startswith("오류 유형:"):
                                        error_type = line.split(":", 1)[1].strip()
                                    elif line.startswith("오류 메시지:"):
                                        error_msg = line.split(":", 1)[1].strip()
                                if error_type or error_msg:
                                    https_errors.append(f"Port {port}: {error_type} - {error_msg}")
                        except Exception:
                            https_errors.append(f"Port {port}: 오류 파일 읽기 실패")
                https_error_str = "; ".join(https_errors) if https_errors else ""

                # SMB 정보 추가
                smb_status = "Y" if result['smb']['open'] else "N"
                smb_ports = ";".join(map(str, result['smb']['ports'])) if result['smb']['ports'] else ""

                # FTP 정보 추가
                ftp_status = "Y" if result['ftp']['open'] else "N"
                ftp_ports = ";".join(map(str, result['ftp']['ports'])) if result['ftp']['ports'] else ""
                
                writer.writerow([
                    target, 
                    responsive_status,
                    ssh_status, ssh_ports, 
                    rdp_status, rdp_ports, 
<<<<<<< HEAD
                    http_status, http_ports, http_error_str,
                    https_status, https_ports, https_error_str
=======
                    http_status, http_ports, 
                    https_status, https_ports,
                    smb_status, smb_ports, # SMB 추가
                    ftp_status, ftp_ports  # FTP 추가
>>>>>>> origin/v1.1
                ])
        
        logger.info(f"CSV 보고서가 {report_path}에 생성되었습니다")
        return report_path
       
    def run(self):
        """전체 보안 스캔 프로세스를 실행합니다."""
        # 대상 읽기
        self.read_targets()
        
        if not self.targets:
            logger.error("유효한 대상이 없습니다. 종료합니다.")
            sys.exit(1)
        
        # 모든 호스트에 대해 초기 포트 스캔 수행
        logger.info("모든 대상에 대해 초기 포트 스캔 수행 중...")
        self.responsive_hosts = self.scan_all_targets()
        
        responsive_count = sum(1 for result in self.responsive_hosts.values() if result['responsive'])
        if responsive_count == 0:
            logger.warning("응답하는 호스트가 없습니다. 종료합니다.")
            
            # 비응답 호스트를 결과에 포함
            for target, scan_info in self.responsive_hosts.items():
                self.scan_results[target] = self.prepare_detailed_scan(scan_info)
                
            # 보고서는 생성
            self.generate_markdown_report()
            self.generate_html_report()
            self.generate_csv_report()
            
            # 웹드라이버 종료
            if hasattr(self, 'driver') and self.driver is not None:
                self.driver.quit()
            
            logger.info("보안 스캔이 완료되었습니다 (응답 호스트 없음)")
            return
        
        # 응답한 호스트에 대해서만 상세 서비스 점검 수행
        logger.info(f"응답한 {responsive_count}개 호스트에 대해 상세 서비스 점검 수행 중...")
        for target, scan_info in self.responsive_hosts.items():
            if scan_info['responsive']:
                # 초기 스캔 결과에서 상세 점검을 위한 구조로 변환
                detailed_result = self.prepare_detailed_scan(scan_info)
                
                # 서비스 연결 확인 및 스크린샷 캡처
                checked_result = self.check_services(detailed_result)
                self.scan_results[target] = checked_result
            else:
                # 응답하지 않는 호스트는 스크린샷 필드만 추가하여 결과에 포함
                self.scan_results[target] = self.prepare_detailed_scan(scan_info)
        
        # 보고서 생성
        self.generate_markdown_report()
        self.generate_html_report()
        self.generate_csv_report()
        
        # 웹드라이버 종료
        if hasattr(self, 'driver') and self.driver is not None:
            self.driver.quit()
        
        logger.info("보안 스캔이 성공적으로 완료되었습니다")

def main():
    parser = argparse.ArgumentParser(description='보안 스캐너 도구')
    parser.add_argument('--target-file', '-t', default='target.txt', 
                        help='대상 IP 주소가 포함된 파일 경로 (기본값: target.txt). 한 줄에 하나씩 IP, 호스트명 또는 CIDR 표기법을 사용합니다.')
    args = parser.parse_args()
    
    scanner = SecurityScanner(args.target_file)
    scanner.run()

if __name__ == "__main__":
    main()