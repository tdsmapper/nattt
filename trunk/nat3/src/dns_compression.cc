#include <iostream>
#include <list>

#include "dns_compression.h"
#include "dns_name.h"
#include "types.h"
#include "functions.h"

using namespace std;

size_t DnsCompression::add_name(DnsName &name, size_t offset, uint16_t &ptr) {
    list<string *> &p = name.m_parts;

    for (size_t i = p.size(); i > 0; --i) {
        string res;
        int skip;
        list_to_string(p, (int)i, res, skip);

        if (locate(res, ptr))
            return p.size() - i;
        else
            m_names[res] = offset + skip;
    }

    return p.size();
}

void DnsCompression::list_to_string(list<string *> &parts, int num,
        string &res, int &skip) {
    res.clear();
    list<string *>::reverse_iterator i = parts.rbegin();

    /* get the last num parts */
    for (int j = 0; j < num && i != parts.rend(); ++j, ++i)
        res += "." + **i;

    /* include the length of the first parts as the skip */
    for (skip = 0; i != parts.rend(); ++i)
        skip += (*i)->size() + 1;
}

bool DnsCompression::locate(string &s, uint16_t &r) {
    map<string, uint16_t>::iterator i = m_names.find(s);
    if (i != m_names.end()) {
        r = i->second;
        return true;
    }
    return false;
}

void DnsCompression::dump(void) {
    map<string, uint16_t>::iterator i;

    for (i = m_names.begin(); i != m_names.end(); ++i)
        cout << i->first << " at offset " << i->second << endl;
}
