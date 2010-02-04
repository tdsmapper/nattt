#include <fstream>

#include "config_file.h"
#include "tun_defs.h"
#include "types.h"
#include "functions.h"

using namespace std;

#define xstr(s) str(s)
#define str(s) #s

ConfigFile::ConfigFile() : m_error(NULL) {
    // load defaults
    m_options["port"] = xstr(NAT3_DEFAULT_PORT);

    /* consider these?
    m_options["local_net"] = xstr(NAT3_LOCAL_NAT);
    m_options["local_netmask"] = xstr(NAT3_LOCAL_NETMASK);
    */
}

bool ConfigFile::load(const string &file) {
    string line;
    ifstream fin(file.c_str());

    if (!fin) {
        m_error = "Could not open configuration file";
        return false;
    }

    try {
        while (getline(fin, m_line))
            parse_option();
    }
    catch (const char *s) {
        m_error = s;
        return false;
    }

    fin.close();

    return true;
}

const string *ConfigFile::get(const std::string &option) {
    map<string,string>::iterator i = m_options.find(option);

    if (i == m_options.end())
        return NULL;

    return &i->second;
}

void ConfigFile::parse_option() {
    string name, value;
    m_offset = 0;

    // skip leading spaces
    skip_space();

    // skip comments and blank lines
    if (m_offset == m_line.length() || m_line[m_offset] == '#')
        return;

    get_string(name);
    skip_space();
    get_char('=');
    skip_space();
    get_string(value);

    // store it
    m_options[name] = value;
}

void ConfigFile::skip_space() {
    while (isspace(m_line[m_offset]) && m_offset < m_line.length())
        ++m_offset;
}

void ConfigFile::get_string(string &r) {
    size_t begin = m_offset;

    while (!isspace(m_line[m_offset]) && m_offset < m_line.length())
        ++m_offset;

    if (m_offset == begin)
        throw "No string found";

    r = m_line.substr(begin, m_offset - begin);
}

void ConfigFile::get_char(char v) {
    if (m_line[m_offset] != v)
        throw "Unexpected character on input";
    ++m_offset;
}
