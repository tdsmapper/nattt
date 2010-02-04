#ifndef __DNS_NAME_H__
#define __DNS_NAME_H__

#include <list>
#include <string>
#include <vector>

#include <sys/types.h>

#ifdef DEBUG
#include <iostream>
#endif

typedef unsigned char u_char;

class DnsCompression;

class DnsName
{
  public:
    DnsName(std::string &);
    DnsName(const DnsName &);
    ~DnsName();

    static DnsName *from_wire(u_char *, size_t, size_t &);
    int to_wire(std::vector<u_char> &, DnsCompression &);

#ifdef DEBUG
    void display_name(std::string &);
#endif

  private:
    DnsName(std::list<std::string *> &, size_t);
    // void add_part(std::string &);
    static void empty_list(std::list<std::string *> &);
    static bool read_name(u_char *, size_t, size_t &,
        std::list<std::string *> &, size_t &);

    std::list<std::string *> m_parts;
    size_t m_length;

    // DnsCompression needs access to m_parts
    friend class DnsCompression;
};

#endif /* __DNS_NAME_H__ */
