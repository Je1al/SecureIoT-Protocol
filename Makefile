CXX ?= c++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pedantic

SENDER_SRCS = demo_sender.cpp encryption.cpp hash.cpp nonce.cpp packet.cpp
RECEIVER_SRCS = demo_receiver.cpp encryption.cpp hash.cpp replay_protection.cpp packet.cpp

.PHONY: all sender receiver clean

all: sender receiver

sender: demo_sender

receiver: demo_receiver

demo_sender: $(SENDER_SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $(SENDER_SRCS)

demo_receiver: $(RECEIVER_SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $(RECEIVER_SRCS)

clean:
	rm -f demo_sender demo_receiver
