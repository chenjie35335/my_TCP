SOURCE = $(shell find $(abspath ./Protocol) -name "*.cpp" -or -name "*.h")
CLIENT = $(shell find $(abspath ./client)   -name "*.cpp" -or -name "*.h")
SERVER = $(shell find $(abspath ./server)   -name "*.cpp" -or -name "*.h")
CLIENT_PATH = ./client
SERVER_PATH = ./server
CLIENT_BIN = $(abspath ./client/client)
SERVER_BIN = $(abspath ./server/server)

$(CLIENT_BIN):
	g++ $(SOURCE) $(CLIENT) -o $(CLIENT_BIN) -lpcap

$(SERVER_BIN):
	g++ $(SOURCE) $(SERVER) -o $(SERVER_BIN) -lpcap

all:$(SOURCE) $(CLIENT) $(SERVER)
	make $(CLIENT_BIN)
	make $(SERVER_BIN)

client:
	cd $(CLIENT_PATH) &&  sudo $(CLIENT_BIN)

server:
	cd $(SERVER_PATH) && sudo $(SERVER_BIN)

clean:
	rm -rf $(CLIENT_BIN)
	rm -rf $(SERVER_BIN)


.PHONY: all client server

