# Stage 1: Build the application
FROM maven:3.9.6-eclipse-temurin-21-alpine AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mkdir -p src/main/resources/keys && \
    openssl genpkey -algorithm RSA -out src/main/resources/keys/private.pem -pkeyopt rsa_keygen_bits:2048 && \
    openssl pkey -in src/main/resources/keys/private.pem -pubout -out src/main/resources/keys/public.pem
RUN mvn clean package -DskipTests

# Stage 2: Run the application
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/target/authentication-system-0.0.1-SNAPSHOT.jar app.jar

# Standard port for Spring Boot
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
