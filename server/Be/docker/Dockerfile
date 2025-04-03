# 1. 베이스 이미지 (JDK 17 버전 사용)
FROM openjdk:17-jdk-slim

### Dockerfile 내에서 사용할 변수 JAR_FILE을 정의한다.
ARG JAR_FILE=build/libs/*.jar

# 2. JAR 복사 (이미지에 포함될 파일)
COPY ${JAR_FILE} spring.jar

# 4. 컨테이너 실행 시 실행할 명령어
ENTRYPOINT ["java", "-jar", "/app.jar"]
