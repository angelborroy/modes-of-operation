FROM maven AS build

# Set the working directory inside the container
WORKDIR /app

# Clone the project
RUN git clone https://github.com/angelborroy/modes-of-operation.git

# Run Maven to compile the project and download dependencies
RUN cd modes-of-operation && mvn clean package

# Set the volume where the encrypted BMP files will be saved
RUN mkdir -p /Users/aborroy/Downloads/usj/tmp

# Run the application
ENTRYPOINT ["java", "-cp", "/app/modes-of-operation/target/classes", "es.usj.crypto.cipher.ModesOfOperationComparator"]