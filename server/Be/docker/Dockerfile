# 1. 베이스 이미지 (JDK 17 버전 사용)
FROM openjdk:17-jdk-slim

# 2. JAR 복사 (이미지에 포함될 파일)
COPY build/libs/*.jar app.jar

# 3. 포트 열기 (선택)
EXPOSE 8080

# 4. 컨테이너 실행 시 실행할 명령어
ENTRYPOINT ["java", "-jar", "/app.jar"]
f