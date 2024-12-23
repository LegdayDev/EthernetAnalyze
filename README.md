## Ethernet 헤더 구조
![image](https://github.com/user-attachments/assets/2d9a3fee-2d30-473c-b03a-7a85c0d488b5)

## Ethernet 헤더 C 구현코드
```c
#pragma pack(push, 1)
typedef struct EtherHeader {
	unsigned char dstMac[6]; // 목적지 주서
	unsigned char srcMac[6]; // 출발지 주소
	unsigned short type;     // Payload 타입
} EtherHeader;
#pragma pack(pop)
```
- #pragma pack(push, 1) 을 선언하여 구조체 각 필드들이 메모리상에서 1Byte 씩 정렬되도록 선언
- #pragma pack(pop) 구조체 선언 이후 메모리 정렬 방식 복원

## Ethernet 헤더 출력
- 실제 네트워크에서 이동하는 L2 Frame 을 `EtherHeader` 타입으로 강제 형변환 하여 L2 프레임으로 맞춘 후 출력

  ![image](https://github.com/user-attachments/assets/fef47391-c3ba-4f55-8d73-824ed43f096a)
