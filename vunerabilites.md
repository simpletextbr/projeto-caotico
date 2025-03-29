

## Overview

                    │                   Analyzed Image                     
────────────────────┼──────────────────────────────────────────────────────
  Target            │  wesleypraca/imagem-caotica:latest                   
    digest          │  e0e94c00dbbf                                        
    platform        │ linux/arm64/v8                                       
    provenance      │ https://github.com/simpletextbr/projeto-caotico.git  
                    │  https://github.com/simpletextbr/projeto-caotico/blob/59c7bab26b1a9b5253f29435cb61efeff2f6886b            
    vulnerabilities │    0C     2H     1M     1L                           
    size            │ 70 MB                                                
    packages        │ 413                                                  


## Packages and Vulnerabilities

   0C     1H     0M     1L  ip 2.0.0
pkg:npm/ip@2.0.0

    ✗ HIGH CVE-2024-29415 [Server-Side Request Forgery (SSRF)]
      https://scout.docker.com/v/CVE-2024-29415?s=github&n=ip&t=npm&vr=%3C%3D2.0.1
      Affected range : <=2.0.1                                       
      Fixed version  : not fixed                                     
      CVSS Score     : 8.1                                           
      CVSS Vector    : CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H  
    
    ✗ LOW CVE-2023-42282 [Server-Side Request Forgery (SSRF)]
      https://scout.docker.com/v/CVE-2023-42282?s=github&n=ip&t=npm&vr=%3E%3D2.0.0%2C%3C2.0.1
      Affected range : >=2.0.0  
                     : <2.0.1   
      Fixed version  : 2.0.1    
    

   0C     1H     0M     0L  cross-spawn 7.0.3
pkg:npm/cross-spawn@7.0.3

    ✗ HIGH CVE-2024-21538 [Inefficient Regular Expression Complexity]
      https://scout.docker.com/v/CVE-2024-21538?s=github&n=cross-spawn&t=npm&vr=%3E%3D7.0.0%2C%3C7.0.5
      Affected range : >=7.0.0                                       
                     : <7.0.5                                        
      Fixed version  : 7.0.5                                         
      CVSS Score     : 7.5                                           
      CVSS Vector    : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H  
    

   0C     0H     1M     0L  tar 6.2.0
pkg:npm/tar@6.2.0

    ✗ MEDIUM CVE-2024-28863 [Uncontrolled Resource Consumption]
      https://scout.docker.com/v/CVE-2024-28863?s=github&n=tar&t=npm&vr=%3C6.2.1
      Affected range : <6.2.1                                        
      Fixed version  : 6.2.1                                         
      CVSS Score     : 6.5                                           
      CVSS Vector    : CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H  
    


4 vulnerabilities found in 3 packages
  CRITICAL  0  
  HIGH      2  
  MEDIUM    1  
  LOW       1  

