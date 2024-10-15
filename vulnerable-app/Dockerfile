FROM docker.io/openjdk:8u181-jdk-alpine AS build

WORKDIR /app

RUN apk --no-cache add maven

COPY pom.xml ./
COPY src src

RUN mvn package

FROM docker.io/openjdk:8u181-jre-alpine

WORKDIR /app

COPY --from=build /app/target/target-app-1.0-SNAPSHOT.jar ./vulnerable-app.jar

CMD ["java", "-cp", "./vulnerable-app.jar", "App", "listen-any"]
