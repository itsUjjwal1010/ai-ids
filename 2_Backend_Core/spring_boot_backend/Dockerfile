# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — BUILD
# Uses Maven + JDK 22 to compile and package the Spring Boot app into a JAR
# ─────────────────────────────────────────────────────────────────────────────
FROM maven:3.9.6-eclipse-temurin-22 AS builder

WORKDIR /app

# Copy pom.xml first so Maven can download dependencies (cached layer)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy the full source and build the fat JAR
COPY src ./src
RUN mvn clean package -DskipTests -B

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — RUN
# Lightweight JRE-only image — much smaller than the full JDK builder image
# ─────────────────────────────────────────────────────────────────────────────
FROM eclipse-temurin:22-jre-alpine

WORKDIR /app

# Copy only the built JAR from the builder stage
COPY --from=builder /app/target/ids-dashboard-1.0.0.jar app.jar

# Render injects the PORT env variable — Spring Boot reads it via ${PORT:8080}
EXPOSE 8080

# Java module flags required for Spring Boot + Java 22 compatibility
ENTRYPOINT ["java", \
  "--add-opens", "java.base/java.lang=ALL-UNNAMED", \
  "--add-opens", "java.base/java.util=ALL-UNNAMED", \
  "-jar", "app.jar"]
