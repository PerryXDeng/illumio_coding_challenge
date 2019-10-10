class Firewall:
  def __init__(self, csv_filepath:str):
    """
    behaves as requested
    :param csv_filepath: filepath for the csv
    """
    # # storing the rules in a logically multidimensional integer array cached in CPU for super fast O(1) access time
    # # however, can be inefficient memory wise when there aren't a lot of rules
    # # each axis specify inbound/outbound, tcp/udp, port number, and start/end of IP range
    # # uses 8 byte unsigned integer, data structure uses 4 gig
    # import numpy as np
    # self.rules_tensor = np.empty((2, 2, 65536, 2), dtype=np.dtype('u8'))

    # instead of using an array for super fast access and large memory usage
    # use a dictionary hash map of port - rules
    # sacrifices super fast access time for much lower memory consumption when there aren't many rules
    # theoretical access time for hash map is O(1), but slower than a rules tensor due to cache locality
    # access time of such a map is O(logN) using a sorted tree
    # one map for udp protocol, onr map for tcp protocol
    # positive port number is outbound, negative port number is inbound
    # each value will consist of a tuple of size 4 integer arrays, representing IPv4 address range
    self.tcp_ports = {}
    self.udp_ports = {}
    with open(csv_filepath) as text_stream:
      for info in map(_parse_rule, text_stream):
        _write_rule(info, self.tcp_ports, self.udp_ports)

  def accept_packet(self, direction:str, protocol:str, port:int, ip_address:str):
    """
    behaves as expected
    :param direction:
    :param protocol:
    :param port:
    :param ip_address:
    :return:
    """
    return self._match_rule(protocol, direction, port, ip_address)

  def _match_rule(self, protocol:str, direction:str, port:int, addr:str):
    """
    self explanatory
    :param protocol:
    :param direction:
    :param port:
    :param addr:
    :return: boolean
    """
    rulebook = self.tcp_ports if protocol == 'tcp' else self.udp_ports
    outbound = True if direction == 'outbound' else False
    key = _calculate_key(port, outbound)
    if key not in rulebook:
      return False
    addr_range = rulebook[key]
    range_start = addr_range[0]
    range_end = addr_range[1]
    ip_nums = [int(num) for num in addr.split('.')]
    for i, num in enumerate(ip_nums):
      # check ip in range, by octets
      if num < range_start[i] or num > range_end[i]:
        return False
    return True

### static methods used to init Firewall class ###
def _parse_rule(line:str):
  """
  method name explains itself
  :param line: a line from the csv
  :return: whether it is tcp, whether it is outbound, a port range, and an IPv4 address range
  """
  splitted = line.split(',')
  outbound = True if splitted[0] == 'outbound' else False
  tcp = True if splitted[1] == 'tcp' else False

  ports = [int(num) for num in splitted[2].split('-')]
  port0 = ports[0]
  port1 = port0 if len(ports) == 1 else ports[1]

  addrs = splitted[3].split('-')
  addrs = [[int(num) for num in addr.split('.')] for addr in addrs]
  addr0 = addrs[0]
  addr1 = addr0 if len(addrs) == 1 else addrs[1]

  return tcp, outbound, port0, port1, addr0, addr1


def _write_rule(rule:tuple, tcp_ports:dict, udp_ports:dict):
  """
  method name explains itself
  :param rule: relevant information from file parsing
  :param tcp_ports: rulebook for tcp
  :param udp_ports: rulebook for udp
  :return: nothing
  """
  tcp, outbound, port0, port1, addr0, addr1 = rule
  rulebook = tcp_ports if tcp else udp_ports
  for port in range(port0, port1 + 1):
    key = _calculate_key(port, outbound)
    rulebook[key] = (addr0, addr1)

def _calculate_key(port:int, outbound:bool):
  return port if outbound else -1 * port
