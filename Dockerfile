FROM alpine:latest

# Install necessary packages
RUN apk add --no-cache bash curl drill coreutils


# Copy the script into the container
COPY eov.sh /usr/local/bin/eov.sh

# Make the script executable
RUN chmod +x /usr/local/bin/eov.sh

# Set the entry point to the script
ENTRYPOINT ["/usr/local/bin/eov.sh"]