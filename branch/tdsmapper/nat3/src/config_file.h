#ifndef __CONFIG_FILE_H__
#define __CONFIG_FILE_H__

#include <map>
#include <string>

class ConfigFile {
    public:
        ConfigFile();

        bool load(const std::string &);
        const std::string *get(const std::string &);

        inline const char *error() { return m_error; }

    private:
        std::map<std::string, std::string> m_options;
        std::string m_line;
        size_t m_offset;
        const char *m_error;

        void parse_option();
        void skip_space();
        void get_string(std::string &);
        void get_char(char);
};

#endif /* __CONFIG_FILE_H__ */
