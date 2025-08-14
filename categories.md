# Categories of Kali Linux Tools
> Tổng hợp & phân loại công cụ theo luồng tấn công/pentest. Ngôn ngữ: **vi**  

## Mục lục
- [01 – Reconnaissance (trinh sát/thu thập thông tin ban đầu)](#01--reconnaissance-trinh-sátthu-thập-thông-tin-ban-đầu)
- [02 – Resource Development (chuẩn bị tài nguyên)](#02--resource-development-chuẩn-bị-tài-nguyên)
- [03 – Initial Access (xâm nhập ban đầu)](#03--initial-access-xâm-nhập-ban-đầu)
- [04 – Execution (thực thi payloadlệnh)](#04--execution-thực-thi-payloadlệnh)
- [05 – Persistence (duy trì hiện diện)](#05--persistence-duy-trì-hiện-diện)
- [06 – Privilege Escalation (leo thang đặc quyền)](#06--privilege-escalation-leo-thang-đặc-quyền)
- [07 – Defense Evasion (né phát hiện/che giấu)](#07--defense-evasion-né-phát-hiệnche-giấu)
- [08 – Credential Access (thu/bẻ mật khẩu)](#08--credential-access-thubẻ-mật-khẩu)
- [09 – Discovery (khám phá nội bộ)](#09--discovery-khám-phá-nội-bộ)
- [10 – Lateral Movement (di chuyển ngang)](#10--lateral-movement-di-chuyển-ngang)
- [11 – Collection (thu thập dữ liệu)](#11--collection-thu-thập-dữ-liệu)
- [12 – Command & Control (C2 / điều khiển)](#12--command--control-c2--điều-khiển)
- [13 – Exfiltration (rút dữ liệu)](#13--exfiltration-rút-dữ-liệu)
- [14 – Impact (tác động/DoS, gây gián đoạn)](#14--impact-tác-độngdos-gây-gián-đoạn)
- [15 – Forensics (pháp y số)](#15--forensics-pháp-y-số)
- [16 – Services & Other Tools (dịch vụ & tiện ích)](#16--services--other-tools-dịch-vụ--tiện-ích)
- [Attack Flow](#attack-flow)

---

## 01 – Reconnaissance (trinh sát/thu thập thông tin ban đầu)
- Bước đầu của pentest/red team: gom dữ liệu công khai/ít gây chú ý để hiểu **bề mặt tấn công** trước khi quét sâu/khai thác.
- Hai kiểu:
  - **Passive recon**: OSINT, search engines, DNS công khai… → ít log/ít ồn.
  - **Active recon**: truy vấn trực tiếp mục tiêu (DNS brute-force, HTTP fingerprinting…) → nhanh/giàu dữ liệu nhưng dễ bị phát hiện.
- Nhóm công cụ:
  - **OSINT & subdomain**: theHarvester, Amass, Sublist3r, SpiderFoot, Maltego CE, Recon-NG  
  - **DNS & hạ tầng**: DNSrecon, DNSenum, Fierce  
  - **Fingerprinting & WAF**: WhatWeb, WAFW00F  
  - **Tài liệu & typosquatting**: Metagoofil, urlcrazy  

**Quy trình mẫu**
1) Xác định phạm vi (domain, công ty mẹ, ASN, dải IP công khai).  
2) Passive subdomain + email:
```bash
amass enum -passive -d example.com -o amass.txt
theHarvester -d example.com -b all -l 200 -f harvest.html
sublist3r -d example.com -o s3.txt
