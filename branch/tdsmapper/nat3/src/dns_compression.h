#ifndef __DNS_COMPRESSION_H__
#define __DNS_COMPRESSION_H__

#ifndef _MSC_VER
   #include <stdint.h>
#endif
#include <map>
#include <list>
#include <string>

#include "types.h"
#include "functions.h"

class DnsName;

class DnsCompression {
    public:
        size_t add_name(DnsName &, size_t, uint16_t &);

    private:
        std::map<std::string, uint16_t> m_names;

        void list_to_string(std::list<std::string *> &, int, std::string &,
                int &);
        bool locate(std::string &, uint16_t &);
        void dump(void);
};

#endif /* __DNS_COMPRESSION_H__ */
