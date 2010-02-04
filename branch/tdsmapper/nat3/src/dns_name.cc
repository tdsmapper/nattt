#include <assert.h>

#include "dns_name.h"
#include "dns_compression.h"
#include "dns_header.h" // for header size
#include "types.h"
#include "functions.h"
#ifndef _MSC_VER
   #include <limits.h>
#endif


using namespace std;

// to make a name from a FQDN
DnsName::DnsName(string &name)
{
 m_length = name.length();

 size_t index = 0, pos;
 while ((pos = name.find_first_of(".", index)) != string::npos)
 {
   string *new_part = new string();
   new_part->append(name, index, pos - index);
   m_parts.push_back(new_part);
   index = pos + 1;
 }
}

// constructor is private
DnsName::DnsName(list<string *> &parts, size_t len)
  : m_length(len)
{
  // copy the list in efficiently
  m_parts.splice(m_parts.begin(), parts);
}

DnsName::~DnsName()
{
  empty_list(m_parts);
}

// copy constructor
DnsName::DnsName(const DnsName &n)
{
  m_length = n.m_length;
  
  for (list<string *>::const_iterator i = n.m_parts.begin();
      i != n.m_parts.end(); ++i)
  {
    m_parts.push_back(new string(**i));
  }
}

DnsName *DnsName::from_wire(u_char *bytes, size_t size, size_t &offset)
{
  DnsName *ret = NULL;
  list<string *> parts;
  size_t len = 0;

  if (read_name(bytes, size, offset, parts, len))
  {
    ret = new DnsName(parts, len + 1);
  }

  return ret;
}

// copy a name out of the RR (w/ compression) into a list
bool DnsName::read_name(u_char *bytes, size_t size, size_t &offset,
    list<string *> &parts, size_t &len)
{
  u_char nlen;
  bool ok = true;

  for ( ; ; )
  {
    // never read past the end of the buffer
    if (offset >= size)
    {
      ok = false;
      break;
    }

    // get the length of the next part of the name
    nlen = bytes[offset++];

    // if it's 0, we're done
    if (nlen == 0)
    {
      break;
    }

    // jump to pointer
    if (nlen > 63)
    {
      // compression is two octets long
      if (offset == size)
      {
        ok = false;
        break;
      }

      size_t t_offset = ((nlen & 63) << 8) + bytes[offset++];
      // try to recursively get the rest
      if (nlen < 192 || !read_name(bytes, size, t_offset, parts, len))
      {
        ok = false;
      }
      break;
    }

    len += nlen + 1;

    // copy the name part
    string *new_part = new string();
    new_part->reserve(nlen);
    for ( ; nlen > 0; --nlen, ++offset)
      new_part->append(1, (char)tolower(bytes[offset]));

    parts.push_back(new_part);
  }

  if (!ok)
  {
    empty_list(parts);
  }

  return ok;
}

int DnsName::to_wire(vector<u_char> &dest, DnsCompression &compression)
{
  int len = 0;

  uint16_t ptr;
  size_t parts = compression.add_name(*this, dest.size(), ptr);
  bool compressed = parts < m_parts.size();

  // copy each name part into the packet
  list<string *>::iterator i;
  for (i = m_parts.begin(); parts > 0 && i != m_parts.end(); --parts, ++i)
  {
    string *cur = *i;
    dest.push_back((u_char)cur->length());

    // copy the string itself
    for (unsigned j = 0; j < cur->length(); ++j)
      dest.push_back(cur->at(j));
	assert (cur->size() < INT_MAX); // Since we convert from cur->size (uint/size_t) to int
    len += (unsigned int)(cur->size()) + 1;
  }

  if (compressed) {
    dest.push_back(((ptr >> 8) & 0xff) | 0xc0);
    dest.push_back(ptr & 0xff);
    len += 2;
  }
  else {
    dest.push_back(0);
    ++len;
  }

  return len;
}

void DnsName::empty_list(list<string *> &parts)
{
  for (list<string *>::iterator i = parts.begin(); i != parts.end(); ++i)
  {
    delete *i;
  }
}

#ifdef DEBUG

void DnsName::display_name(std::string &print)
{
  print.clear();
  print.reserve(m_length);

  for (list<string *>::iterator i = m_parts.begin(); i != m_parts.end(); ++i)
  {
    print.append(**i);
    print.append(1, '.');
  }
}

#endif
