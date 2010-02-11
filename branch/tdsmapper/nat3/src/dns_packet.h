#ifndef __DNS_PACKET_H__
#define __DNS_PACKET_H__

#include <vector>
#include "datatypes.h"
#include "dns_header.h"

class DnsRR;
class DnsHeader;

class DnsPacket
{
  public:
    DnsPacket(int size = 512);
    DnsPacket(bool question, int);
    ~DnsPacket();

    // add bytes from the wire
    void add_bytes(unsigned char *bytes, size_t count);

    // get wire representation
    void to_wire(vector<u_char> &);
    u_char *get_bytes(size_t &);
    bool parse();
    DnsHeader& header(void);
    DnsHeader* getHdr();

    const std::vector<DnsRR *> &questions(void);
    const std::vector<DnsRR *> &answers(void);

    void add_question(DnsRR &);
    void add_answer(DnsRR &);

  private:
    void clear_vectors();
    std::vector<unsigned char> m_bytes;
    bool m_parsed;
    std::vector<DnsRR *> m_qd, m_an, m_ns, m_ar;
    DnsHeader *m_header;
};

#endif
