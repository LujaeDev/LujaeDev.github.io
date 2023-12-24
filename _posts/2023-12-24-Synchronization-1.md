---
title: Collaborative Editing 구현 - 1
author: lujae
date: 2023-12-24 00:34:00 +0800
categories: [Synchronization]
tags: [Synchronization]
toc: true
---

동기화는 영어로 Synchronization이다. 정보를 일치시키는 것을 의미한다. 어떤 정보를 단일 개체만 알고 있을 경우 일치시킬 노력 없이 해당 정보는 일치된 상태를 유지한다. 하지만 어떤 정보에 대해 A라는 개체, B라는 개체가 알고 있는 것이 다르다면 A와 B가 의사소통할 때 문제를 발생할 수 있으므로, 개체 A, B간의 정보를 일치시켜야 하며 이를 Synchronization이라 한다.

이번 한 해 동안 학교 공부를 하면서 삼성 노트라는 어플리케이션으로 필기를 많이 했는데 다양한 기기로 하나의 파일에 접근할 때 정보가 실시간으로 최신화 되는 것이 너무 신기했다. 그리고 이런 경험으로 인해 클라우드와 Synchronization 기술에 관심이 생겼다. 그런데 사실 이런 Synchronization 기술은 Google docs, notion 등 과 같은 협업 관련 서비스에서도 많이 활용하고 있는 기술이다. 그래서 Google docs처럼 여러 사용자가 동시에 편집할 수 있는 기능을 담은 토이 프로젝트를 할 생각이다.

## Google docs 분석

### `기능 사항`

1. **Collaboration**: 여러 사용자는 동시에 하나의 문서에서 작업을 할 수 있어야한다.

2. **Confilct resolution**: 다른 사용자와 동시에 작업을 할 때, 같은 부분에 대해 작업을 할 경우 이를 처리할 수 있어야한다.

3. **Permission**: 모든 사용자가 해당 문서에 수정 가능한 것은 아니다. 한 문서에 대해 어떤 사용자는 읽기만 가능한 것인지, 읽기 쓰기 모두 가능한 것인지 권한을 부여할 수 있어야 한다.

4. **History**: 한 문서에 어떤 사용자가 어떤 작업을 했는지 시간별, 사용자별로 정렬하여 볼 수 있어야 한다. 또한 각 사용자가 수행한 작업을 각 사용자만 취소할 수 있어야한다.

### `통신 프로토콜`

#### HTTP ?

웹에서 현재 가장 많이 쓰이는 통신 프로토콜은 HTTP이다. HTTP는 Client-Server 구조로 Client가 Server로 요청을 보내면 Server는 해당 요청에 대해 응답을 Client로 보내는 방식으로 작동한다. 그리고 HTTP(Application-layer)는 TCP(Transport-layer)를 기반으로 동작하기 때문에 Client-Server간 통신시 3way-handshake로 연결이 됨을 보장한다. 이때 HTTP의 대표적인 특징인 비연결성을 생각하면 통신이 자주 발생하는 상황에서는 사전 작업(3way-handshake)이 오버헤드로 작용할 것이다. 그리고 공유 문서는 항상 통신이 많이 발생할 수 밖에 없는 서비스이므로 HTTP는 적합하지 않다.

#### Web Socket !

HTTP의 단점은 비연결성이므로 연결성을 유지하는 프로토콜을 사용해야만한다. 그리고 실시간으로 양방향 통신이 가능한 Web Socket이 적당한 대안책이다.

### `시스템 디자인`

![GoogleDocs Structure](/assets/img/posts/googledocs_structure.png)

위의 사진은 Medium 아티클에서 발췌한 사진이다. 사진상으로 여러 컴포넌트들이 있는데 해당 컴포넌트들에 잘 알지는 못하기 때문에 저대로 구현 할 수 있을지 잘 모르겠지만, 의미있는 구조라 생각하기에 최대한 저런 구조로 구현할 생각이다.

### `컴포넌트`

- `CDN`: 콘텐츠 전송 네트워크(Contents Delivery Network)의 약자로, 데이터 사용량이 많은 어플리케이션에 연결하는 서버 네트워크이다. 단일 서버로 서비스를 운용하게 되면 해당 서버와 거리가 먼 사용자는 응답을 늦게 받게 되는데 이를 보완하기 위해서 사용한다.

- `Load Balancer`: 여러 대의 서버를 운용하는 경우 각 서버에 작업량(Client의 요청)을 균일하게 배정해주는 역할을 한다.
- `API Gateway`: 현재는 Clinet가 보내는 요청의 `단일 진입점`이라고 생각해도 될 거 같다.
- `RDBMS`: 관계형 데이터베이스의 약자로, 사용자의 정보와 문서 정보를 저장하기 위해 사용한다.
- `Redis`: 사용자 세션, 자주 엑세스하는 문서를 포함한 다양한 데이터를 저장하는 캐시역할로 사용된다.

## 참고

https://contents.premium.naver.com/3mit/wony/contents/221214201647988tf

https://medium.com/@sureshpodeti/system-design-google-docs-93e12133a979

https://velog.io/@julie0005/%EC%8B%A4%EC%8B%9C%EA%B0%84-%EA%B3%B5%EC%9C%A0-%EB%AC%B8%EC%84%9C-%ED%8E%B8%EC%A7%91-%ED%88%B4%EC%9D%84-%EA%B0%9C%EB%B0%9C%ED%95%98%EB%A0%A4%EB%A9%B4-%EB%AC%B4%EC%97%87%EC%9D%84-%EC%9D%B4%ED%95%B4%ED%95%B4%EC%95%BC-%ED%95%98%EB%8A%94%EA%B0%801-%EB%B0%B1%EC%97%94%EB%93%9C
