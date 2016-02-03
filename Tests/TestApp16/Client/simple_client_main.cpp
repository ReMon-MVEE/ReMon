/*
 * Source: http://linuxgazette.net/issue74/tougher.html
 */

#include "ClientSocket.h"
#include "SocketException.h"
#include <iostream>
#include <string>

int main ( int argc, char *argv[] )
{
  try
    {

      ClientSocket client_socket ( "localhost", 30000 );

      std::string reply;

      try
	{
	  client_socket << "Test message.";
	  client_socket >> reply;
	}
      catch ( SocketException& ) {}

      std::cout << "We received this response from the server:\n\"" << reply << "\"\n";;

      std::string ipAddress;
      int port;

      if (client_socket.getpeername(ipAddress, port))
        std::cout << "Peer's IP address: " << ipAddress << ", port: " << port << "\n";

    }
  catch ( SocketException& e )
    {
      std::cout << "Exception was caught:" << e.description() << "\n";
      std::cout << "Is the server running?\n";
    }

  return 0;
}
