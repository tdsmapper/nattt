#ifndef _LRU_CACHE_H
#define _LRU_CACHE_H

#include <list>
#include <map>

#define LRU_DEFAULT_MAX_SIZE 10000

// using namespace std;

template<class K, class V>

//typedef list<K> LruList_t;
//typedef LruList_t::iterator LruListIter_t;

//typedef map<K, V> LruMap_t;
//typedef LruMap_t::iterator LruMapIter_t;

class LruCache
{
  // Member Variables
  private:
    struct list_entry {
      K *key;
      V *value;
      list_entry *prev, *next;
    };

    // simple list class
    class SimpleList
    {
      private:
        list_entry m_dummy;

      public:
        SimpleList()
        {
          m_dummy.next = m_dummy.prev = &m_dummy;
        }

        inline void add_to_head(list_entry *entry)
        {
          entry->next = m_dummy.next;
          entry->prev = &m_dummy;
          m_dummy.next->prev = entry;
          m_dummy.next = entry;
        }

        // remove an item
        inline void remove(list_entry *entry)
        {
          entry->prev->next = entry->next;
          entry->next->prev = entry->prev;
        }

        // remove the tail
        inline list_entry *remove_tail()
        {
          list_entry *ret;

          ret = m_dummy.prev;
          if (ret != NULL)
          {
            remove(ret);
          }

          return ret;
        }

        // true if the entry is the head
        inline bool is_head(list_entry *entry)
        {
          bool ret = false;
          if (m_dummy.next == entry)
          {
            ret = true;
          }
          return ret;
        }

        // destroy all the entries
        void clear()
        {
          list_entry *entry, *next;

          for (entry = m_dummy.next; entry != &m_dummy; entry = next)
          {
            next = entry->next;
            destroy_entry(entry);
            delete entry;
          }

          m_dummy.next = m_dummy.prev = &m_dummy;
        }
    };

    SimpleList m_oList;

    int m_iMaxSize;
    int m_iCurrentSize;
    std::map<K, list_entry *> m_oMap;
    bool m_init;

    // private methods
    struct LruCache<K, V>::list_entry *get_entry(K &p_oKey);
    static void destroy_entry(list_entry *entry);

  // Methods
  public:
    LruCache();
    virtual ~LruCache();

    bool init(int p_iMaxSize = LRU_DEFAULT_MAX_SIZE);

    bool add(K &p_oKey, V &p_oItem);
    V *get(K &p_oKey);
    bool remove(K &p_oKey);

    int size();
    int maxSize();
    float hitRatio();
};

using namespace std;

template<class K, class V>
LruCache<K, V>::LruCache()
 : m_iMaxSize(LRU_DEFAULT_MAX_SIZE),
   m_iCurrentSize(0),
   m_init(false)
{

}

template<class K, class V>
LruCache<K, V>::~LruCache()
{
  m_oList.clear();
}

template<class K, class V>
bool LruCache<K, V>::init(int p_iMaxSize /*= LRU_DEFAULT_MAX_SIZE*/)
{
  m_oMap.clear();
  m_oList.clear();

  m_iCurrentSize = 0;
  m_iMaxSize = p_iMaxSize;
  m_init = true;

  return true;
}

template<class K, class V>
bool LruCache<K, V>::add(K &p_oKey, V &p_oItem)
{
  list_entry *entry;

  // if we're replacing something, this is easy
  entry = get_entry(p_oKey);
  if (entry != NULL)
  {
    m_oList.remove(entry);
    destroy_entry(entry);
  }

  // otherwise, if we have to remove something, remove the last thing
  else if (m_iCurrentSize == m_iMaxSize)
  {
    entry = m_oList.remove_tail();
    m_oMap.erase(*entry->key);
    destroy_entry(entry);
  }

  // otherwise allocate memory for the new list element
  else
  {
    entry = new list_entry;
    ++m_iCurrentSize;
  }

  entry->key = new K(p_oKey);
  entry->value = &p_oItem;

  // add the entry to the head of the list
  m_oList.add_to_head(entry);

  // add it to the map for random access
  m_oMap.insert(make_pair(*entry->key, entry));

  return true;
}

// get a value based on a key
template<class K, class V>
V *LruCache<K, V>::get(K &p_oKey)
{
  V *ret;
  list_entry *entry;

  // locate the list_entry struct
  entry = get_entry(p_oKey);
  if (entry == NULL)
  {
    ret = NULL;
  }

  // if we found it return it
  else
  {
    ret = entry->value;

    // promote it to the front of the list
    if (!m_oList.is_head(entry))
    {
      m_oList.remove(entry);
      m_oList.add_to_head(entry);
    }
  }

  return ret;
}

// explicitly remove an element from the class
template<class K, class V>
bool LruCache<K, V>::remove(K &p_oKey)
{
  bool ret;
  list_entry *entry;

  // attempt to locate the struct
  entry = get_entry(p_oKey);
  if (entry == NULL)
  {
    ret = false;
  }

  // if we find it, remove it from the list and destroy it
  else
  {
    m_oList.remove(entry);
    m_oMap.erase(*entry->key);
    destroy_entry(entry);
    delete entry;
    --m_iCurrentSize;

    ret = true;
  }

  return ret;
}

template<class K, class V>
int LruCache<K, V>::size()
{
  return m_iCurrentSize;
}

template<class K, class V>
int LruCache<K, V>::maxSize()
{
  return m_iMaxSize;
}

template<class K, class V>
float LruCache<K, V>::hitRatio()
{
  return 0.0;
}

// helper function to locate an entry's struct
template<class K, class V>
typename LruCache<K, V>::list_entry * LruCache<K, V>::get_entry(K &p_oKey) // "typename" keyword added for VS2008
{
  list_entry *ret = NULL;

  // try to find it in the map
  typename map<K, list_entry *>::iterator iter = m_oMap.find(p_oKey);
  if (iter != m_oMap.end())
  {
    // ret = m_oMap[p_oKey];//*iter;
    ret = iter->second;
  }

  return ret;
}

template<class K, class V>
void LruCache<K, V>::destroy_entry(struct LruCache<K, V>::list_entry *entry) // "struct" keyword added
{
  // delete entry->key;
  delete entry->value;
}

#endif

