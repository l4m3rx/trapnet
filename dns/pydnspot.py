import socket
import select
import dns.message
import dns.flags
import dns.query
import dns.resolver
import dns.rdataclass
import dns.rdatatype

# Maximum number of requests to serve per IP
MAX_REQUESTS_PER_IP = 5

# Dictionary to keep track of request counts per IP
request_counts = {}

def log_query(ipaddr, protocol, query, response, status, request_count):
    query_type = dns.rdatatype.to_text(query.question[0].rdtype) if query.question else "Unknown"
    requested_domain = query.question[0].name.to_text() if query.question else "Unknown"
    recursion_desired = "true" if query.flags & dns.flags.RD else "false"
    request_size = len(query.to_wire())
    response_size = len(response.to_wire()) if response else 0
    dnssec_used = "true" if any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in response.answer) else "false"

    log_message = (f"[{status}] {protocol}, Count: {request_count}, {ipaddr} Recursion: {recursion_desired}, DNSSec: {dnssec_used}, Sizes: {request_size}/{response_size}, Type: {query_type} Request: {requested_domain}")

    print(log_message)
    # with open("dns_queries.log", "a") as log_file:
    #     log_file.write(log_message + "\n")


def handle_query(data, addr, protocol):
    ipaddr = addr[0]
    try:
        query = dns.message.from_wire(data)
        #domain = query.question[0].name.to_text() if query.question else "Unknown"
        response = dns.message.make_response(query)

        request_counts[ipaddr] = request_counts.get(ipaddr, 0) + 1
        if request_counts.get(ipaddr, 0) >= MAX_REQUESTS_PER_IP:
            log_query(addr[0], protocol, query, response, 'B', request_counts[ipaddr])
            return None  # Blackhole the request

        # Log the allowed query
        log_query(addr[0], protocol, query, response, 'A', request_counts[ipaddr])

        # If not blocked, resolve the domain and create a response
        for question in query.question:
            try:
                answer = dns.resolver.resolve(question.name, question.rdtype)
                for rrset in answer.response.answer:
                    response.answer.append(rrset)
            except dns.resolver.NoAnswer:  # Handle no answer
                response.set_rcode(dns.rcode.NOERROR)
            except dns.resolver.NXDOMAIN:  # Handle domain not found
                response.set_rcode(dns.rcode.NXDOMAIN)

        response.flags |= dns.flags.AA
        return response.to_wire()
    except Exception as err:
        error_message = f"Error handling query from {addr}: {err}"
        print(error_message)
        with open("dns_queries.log", "a") as log_file:
            log_file.write(error_message + "\n")
        return None


def start_dns_server():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        udp_socket.bind(('', 53))
        tcp_socket.bind(('', 53))
        tcp_socket.listen(5)

        print("DNS server running on UDP and TCP...")

        while True:
            readable, _, _ = select.select([udp_socket, tcp_socket], [], [])
            for sock in readable:
                if sock is udp_socket:
                    try:
                        data, addr = udp_socket.recvfrom(512)
                        response = handle_query(data, addr, "UDP")
                        if response:
                            udp_socket.sendto(response, addr)
                    except Exception as err:
                        print(f"Error handling UDP request: {err}")

                elif sock is tcp_socket:
                    try:
                        conn, addr = tcp_socket.accept()
                        with conn:
                            length = conn.recv(2)
                            if not length:
                                continue
                            data_length = int.from_bytes(length, 'big')
                            data = conn.recv(data_length)
                            response = handle_query(data, addr, "TCP")
                            if response:
                                conn.send(len(response).to_bytes(2, 'big') + response)
                    except Exception as err:
                        print(f"Error handling TCP request: {err}")

    except Exception as err:
        print(f"Error in DNS server: {err}")
    finally:
        udp_socket.close()
        tcp_socket.close()


if __name__ == "__main__":
    start_dns_server()
