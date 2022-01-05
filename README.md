# web_hw3
請寫出一個封包檢視工具，具有底下功能：

可以讀入既有的pcap檔案，並對於檔案中的每個封包顯示(每個封包一行)：

1. 那個封包擷取的時間戳記

2. 來源MAC位址、目的MAC位址、Ethernet type欄位

3. 如果那個封包是IP封包，則再多顯示來源IP位址與目的地IP位址

4. 如果那個封包是TCP或UDP封包，則再多顯示來源port號碼與目的port號碼
-------------------------------------------------------------------
操作: make
      
      ./CheckPacket file.pcap (file為pcap檔名)

顯示畫面
      ![image](https://user-images.githubusercontent.com/94603586/148282746-00fe2efc-aea4-48db-a83b-e3117567d275.png)

      id:第幾個封包
      
      Time Mark:時間戳記
      
      MAC address Source:MAC位址來源
      
      MAC address Destination:MAC傳送位址
      
      ----------------------------------------------
      Type:
      
      ipv4:UDP/TCP/else
      
      顯示Source IP address/Destination IP address
      
      如果是UDP/TCP:
         
         顯示Protocol:UDP/TCP
            
            Source Port:來源port
            
            Destination Port:收到port
      
      ----------------------------------------------
      ipv6:UDP/TCP/ICMPv6/else
      
      顯示Source IP address/Destination IP address
      
      如果是UDP/TCP:
         
         顯示Protocol:UDP/TCP
            
            Source Port:來源port
            
            Destination Port:收到port
      
      如果是ICMPv6
          
          顯示Protocol:ICMPv6
      ----------------------------------------------
      其他:
        
        Type: not IP/TCP
