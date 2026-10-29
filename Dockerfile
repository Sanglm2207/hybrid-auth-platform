FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /workspace
COPY . .
ARG MODULE
RUN mvn -q -pl ${MODULE} -am -DskipTests package
FROM eclipse-temurin:25-jre
WORKDIR /app
ARG MODULE
COPY --from=build /workspace/${MODULE}/target/${MODULE}-1.0.0.jar app.jar
USER 10001
ENTRYPOINT ["java","-jar","/app/app.jar"]
