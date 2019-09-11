CXX = c++
CFLAGS = -Os --std=gnu++11 -Wall
LIBS = -lscamperfile
DEPS = ipaddress.hpp yarrpfile.hpp
OBJ = yrp2warts.o

%.o: %.cpp $(DEPS)
	$(CXX) -c -o $@ $< $(CFLAGS)

yrp2warts: $(OBJ)
	$(CXX) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f yrp2warts yrp2warts.o