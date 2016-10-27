/*
  Copyright (C) 2016 Eneo Tecnologia S.L.
  Author: Eugenio Perez <eupm90@gmail.com>
  Based on Luca Deri nprobe 6.22 collector

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as
  published by the Free Software Foundation, either version 3 of the
  License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include "f2k.h"
#include "rb_sensor.h"
#include "template.h"
#include <assert.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <pwd.h>
#include <syslog.h>

#ifdef FREEBSD
#include <pthread_np.h>

typedef cpuset_t cpu_set_t;
#endif


#ifdef __NetBSD__
#include <pthread.h>
#include <sched.h>
#endif


#ifdef sun
extern char *strtok_r(char *, const char *, char **);
#endif

#ifdef HAVE_GEOIP
#define GEOIP_DIR_LOCAL_TEMPLATE "%s"
#define GEOIP_DIR_SYSTEM_TEMPLATE PREFIX "/f2k/%s"
#endif

static char *proto_mapping[0xFF] = { NULL };
static char *vlan_mapping[0xFFFF] = { NULL };

/* ************************************ */

void traceEvent(const int eventTraceLevel, const char* file,
		const int line, const char * format, ...) {
  va_list va_ap;

  if(eventTraceLevel <= readOnlyGlobals.traceLevel) {
    char buf[4096], out_buf[4096-(1024-640)];
    char theDate[32], *extra_msg = "";
    time_t theTime = time(NULL);

    va_start (va_ap, format);

    /* We have two paths - one if we're logging, one if we aren't
     *   Note that the no-log case is those systems which don't support it (WIN32),
     *                                those without the headers !defined(USE_SYSLOG)
     *                                those where it's parametrically off...
     */

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime(&theTime));

    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    if(eventTraceLevel == 0 /* TRACE_ERROR */)
      extra_msg = "ERROR: ";
    else if(eventTraceLevel == 1 /* TRACE_WARNING */)
      extra_msg = "WARNING: ";

    while(buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';

    snprintf(out_buf, sizeof(out_buf)-1, "%s [%s:%d] %s%s", theDate,
	     file,
	     line, extra_msg, buf);

    if(readOnlyGlobals.useSyslog) {
      if(!readWriteGlobals->syslog_opened) {
	openlog(readOnlyGlobals.f2kId, LOG_PID, LOG_DAEMON);
	readWriteGlobals->syslog_opened = 1;
      }

      syslog(LOG_INFO, "%s", out_buf);
    } else
      printf("%s\n", out_buf);
  }

  fflush(stdout);
  va_end(va_ap);
}

/* ********* IP utils ****** */
/*
 * A faster replacement for inet_ntoa().
 */
char* _intoaV4(unsigned int addr, char* buf, size_t bufLen) {
  char *cp, *retStr;
  uint byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
  *--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ****************************** */

char* _intoa(IpAddress addr, char* buf, size_t bufLen) {
  if((addr.ipVersion == 4) || (addr.ipVersion == 0 /* Misconfigured */)){
    return(_intoaV4(addr.ipType.ipv4, buf, bufLen));
  } else {
    char *ret;

    ret = (char*)inet_ntop(AF_INET6, &addr.ipType.ipv6, buf, bufLen);

    if(ret == NULL) {
      traceEvent(TRACE_WARNING, "Internal error (buffer too short)");
      buf[0] = '\0';
    }

    ret = buf;

    return(ret);
  }
}

#ifdef HAVE_GEOIP
static void readGeoIpDatabase(const char *path, const char *database_name, GeoIP ** geo_v4,GeoIP **geo_v6)
{
  assert(geo_v4);
  assert(geo_v6);

  if(path == NULL)
    return;

  pthread_rwlock_wrlock(&readWriteGlobals->geoipRwLock);

  if(*geo_v4){
    traceEvent(TRACE_NORMAL,"Closing %s database",database_name);
    *geo_v4 = NULL;
    GeoIP_delete(*geo_v4);
  }
  if(*geo_v6){
    traceEvent(TRACE_NORMAL,"Closing %s IPV6 database",database_name);
    *geo_v6 = NULL;
    GeoIP_delete(*geo_v6);
  }

  struct stat stats;
  char the_path[256];

  if(stat(path, &stats) == 0)
    snprintf(the_path, sizeof(the_path), GEOIP_DIR_LOCAL_TEMPLATE, path);
  else
    snprintf(the_path, sizeof(the_path), GEOIP_DIR_SYSTEM_TEMPLATE, path);

  if((*geo_v4 = GeoIP_open(the_path, GEOIP_MEMORY_CACHE)) != NULL) {
    traceEvent(TRACE_NORMAL, "GeoIP: loaded %s config file %s", database_name,the_path);
    (*geo_v4)->charset = GEOIP_CHARSET_UTF8;
  }else{
    traceEvent(TRACE_WARNING, "Unable to load %s file %s. %s support disabled", database_name,the_path,database_name);
  }

  /* ********************************************* */

  strcpy(&the_path[strlen(the_path)-4], "v6.dat");

  if((*geo_v6 = GeoIP_open(the_path, GEOIP_MEMORY_CACHE)) != NULL) {
    traceEvent(TRACE_NORMAL, "GeoIP: loaded %s IPv6 config file %s", database_name,the_path);
    (*geo_v6)->charset = GEOIP_CHARSET_UTF8;
  }else{
    traceEvent(TRACE_WARNING, "Unable to load %s IPv6 file %s. AS IPv6 support disabled", database_name,the_path);
  }

  pthread_rwlock_unlock(&readWriteGlobals->geoipRwLock);
}
#endif

void readASs(const char *path) {
#ifdef HAVE_GEOIP
  readGeoIpDatabase(path,"AS",&readOnlyGlobals.geo_ip_asn_db,&readOnlyGlobals.geo_ip_asn_db_v6);
#endif
}

void readCities(const char *path) {
#ifdef HAVE_GEOIP
  readGeoIpDatabase(path,"cities",&readOnlyGlobals.geo_ip_city_db,&readOnlyGlobals.geo_ip_city_db_v6);
#endif
}

void deleteGeoIPDatabases()
{
#ifdef HAVE_GEOIP
  pthread_rwlock_wrlock(&readWriteGlobals->geoipRwLock);
  if(readOnlyGlobals.geo_ip_asn_db != NULL)
    GeoIP_delete(readOnlyGlobals.geo_ip_asn_db);
  readOnlyGlobals.geo_ip_asn_db = NULL;
  if(readOnlyGlobals.geo_ip_asn_db_v6 != NULL)
    GeoIP_delete(readOnlyGlobals.geo_ip_asn_db_v6);
  readOnlyGlobals.geo_ip_asn_db_v6 = NULL;
  if(readOnlyGlobals.geo_ip_city_db != NULL)
    GeoIP_delete(readOnlyGlobals.geo_ip_city_db);
  readOnlyGlobals.geo_ip_city_db = NULL;
  if(readOnlyGlobals.geo_ip_city_db_v6 != NULL)
    GeoIP_delete(readOnlyGlobals.geo_ip_city_db_v6);
  readOnlyGlobals.geo_ip_city_db_v6 = NULL;
  if(readOnlyGlobals.geo_ip_country_db != NULL)
    GeoIP_delete(readOnlyGlobals.geo_ip_country_db);
  readOnlyGlobals.geo_ip_country_db = NULL;
  if(readOnlyGlobals.geo_ip_country_db_v6 != NULL)
    GeoIP_delete(readOnlyGlobals.geo_ip_country_db_v6);
  readOnlyGlobals.geo_ip_country_db_v6 = NULL;
  pthread_rwlock_unlock(&readWriteGlobals->geoipRwLock);
#endif
}

/* ******************************************** */
void readCountries(const char *path) {
#ifdef HAVE_GEOIP
  readGeoIpDatabase(path,"cities",&readOnlyGlobals.geo_ip_country_db,&readOnlyGlobals.geo_ip_country_db_v6);
#endif
}

/* ******************************************** */

#define htonll(x) be64toh(x)

/* ******************************************** */

uint64_t net2number(const char *buffer,const uint16_t real_field_len){
  uint64_t number = 0;

  switch(real_field_len){
  case 1:
    number = *(uint8_t *)buffer;
    break;
  case 2:
    number = ntohs(*(uint16_t *)buffer);
    break;
  case 4:
    number = ntohl(*(uint32_t *)buffer);
    break;
  case 6: /* MAC address case */
    number = (uint64_t)ntohs(*(uint16_t *)buffer)<<32 | ntohl(*(uint32_t *)(buffer+2));
    break;
  case 8:
    number = ntohll(*(uint64_t *)buffer);
    break;
  default:
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_WARNING,"Cannot transform number of size %d:",real_field_len);
  };

  return number;
}

/* ******************************************** */

void load_vlan_mapping(){
  if(readOnlyGlobals.rb_databases.hosts_database_path){
    char * vlanPath = calloc(strlen(readOnlyGlobals.rb_databases.hosts_database_path) + strlen("/vlans") + 1,sizeof(char));
    char * vlanName=NULL;
    char buf[2048];
    strcat(vlanPath,readOnlyGlobals.rb_databases.hosts_database_path);
    strcat(vlanPath,"/vlans");
    FILE * fvlans = fopen(vlanPath,"r");
    if(fvlans==NULL){
      traceEvent(TRACE_WARNING, "Cannot open %s for vlans",vlanPath);
    }else{
      char *strtok_aux = NULL;
      while(NULL!=fgets(buf,2048,fvlans)){
        vlanName = strtok_r(buf," \t", &strtok_aux);
        char * vlanNumber = strtok_r(NULL, " \t", &strtok_aux);
        const int i = strtol(vlanNumber,NULL,10);
        if(errno == EINVAL)
          traceEvent(TRACE_WARNING,"Cannot parse number %s in file %s. Skipping.",vlanNumber,vlanPath);
        else if(vlan_mapping[i])
          traceEvent(TRACE_WARNING,"VLAN number %s was previously setted with value %s. Skipping.",
            vlanNumber,vlan_mapping[i]);
        else
          vlan_mapping[i] = strdup(vlanName);
      }
      fclose(fvlans);
    }
    free(vlanPath);
  }
}

/* ****************************************** */

/* Warning: keep it sync with unload_mapping()! */
void unload_vlan_mapping(){
  int i;
  for(i=0; i<0xFFFF; i++) if(vlan_mapping[i]) free(vlan_mapping[i]);
  memset(vlan_mapping,0,sizeof(char *)*0xFFFF);
}

void load_mappings() {
  struct protoent *pe;

  /* ******************** */

  while((pe = getprotoent()) != NULL) {
    if(proto_mapping[pe->p_proto] == NULL) {
      proto_mapping[pe->p_proto] = strdup(pe->p_name);
      // traceEvent(TRACE_INFO, "[%d][%s]", pe->p_proto, pe->p_name);
    }
  }

  endprotoent();

  load_vlan_mapping();
}

/* ******************************************** */

void unload_mappings() {
  int i;

  for(i=0; i<0xFFFF; i++){
    if(vlan_mapping[i])
      free(vlan_mapping[i]);
  }
  for(i=0; i<0xFF; i++)   if(proto_mapping[i]) free(proto_mapping[i]);
}

/* ******************************************** */

/* FIX: improve performance */
const char* proto2name(uint8_t proto) {
#if 0
  struct protoent *svt;

  if(proto == 6)       return("tcp");
  else if(proto == 17) return("udp");
  else if(proto == 1)  return("icmp");
  else if(proto == 2)  return("igmp");
  else if((svt = getprotobynumber(proto)) != NULL)
    return(svt->p_name);
  else {
    static char the_proto[8];

    snprintf(the_proto, sizeof(the_proto), "%d", proto);
    return(the_proto);
  }
#else
  if(proto_mapping[proto] != NULL) {
    // traceEvent(TRACE_INFO, "[%d][%s]", proto, proto_mapping[proto]);
    return(proto_mapping[proto]);
  } else
    return("unknown");
#endif
}

/* ******************************************** */

struct AS_info
{
  const char *number;
  size_t number_len;
  const char *name;
};

#if 0
static size_t print_twitter_user(struct printbuf *kafka_line_buffer,const char *url)
{
  assert(kafka_line_buffer);
  const char *status = url ? strstr(url,"/status") : NULL;
  if(status)
  {
#define TWITTER_URL "https://twitter.com/"
      const size_t user_len = status-url;
      //printf("Numbers of chars: %d\n",user_len);
      printbuf_memappend_fast(kafka_line_buffer,TWITTER_URL,strlen(TWITTER_URL));
      printbuf_memappend_fast(kafka_line_buffer,url+1,user_len-1);
      return user_len + strlen(TWITTER_URL);
  }
  return 0;
}
#endif

#ifdef TEST_PRINT_TWITTER_USER

void test_print_twitter_user()
{
  struct printbuf *kafka_line_buffer = printbuf_new();

  const char *url1 = "/useruser/stat/foobar";
  const size_t test1 = print_twitter_user(kafka_line_buffer,url1);
  assert(test1==0);
  assert(NULL==strstr(kafka_line_buffer->buf,"useruser"));

  const char *url2 = "/useruser/status/foobar";
  print_twitter_user(kafka_line_buffer,url2);
  if(0!=strcmp(kafka_line_buffer->buf,TWITTER_URL "useruser"))
  {
    fprintf("Expected: %s, actual: %s",TWITTER_URL "useruser", kafka_line_buffer->buf);
    assert("fail"==NULL);
  }
}

#endif

/* Check that nchar characters of str starts with 10xxxxxx, assuming that str is str_len len. */
static int check_multibyte_characters(const char *str,
                const size_t str_len,const size_t nchar) {
  size_t i;
  if(str_len < nchar) {
    /* Not enough spaces */
    return 0;
  }

  for(i=0; i<str_len && i<nchar; ++i) {
    if((str[i] & 0xc0) != 0x80) {
      return 0;
    }
  }

  return 1;
}

/* Return if the next char is a valid UTF-8 char, and it's length.
i.e, it returns:
  1 - Valid 1-byte char
  2 - Valid 2-byte char
  3 - Valid 3-byte char
  4 - Valid 4-byte char
  -1 - Invalid char

  Params:
    to_end -> size of the string from cursor, in bytes
*/
static int valid_utf8_char(const char *cursor,size_t to_end) {
    /* We could do it with a for loop, but there is only this cases */
  unsigned char b = cursor[0];
    if((b & 0x80) == 0) {
      /* ASCII code, we can accept it */
      return 1;
    } else if (b == 0xc0 || b == 0xc1) {
      /* Trying to code ASCII character too long. */
      return -1;
    } else if ((b & 0xe0) == 0xc0) {
      /* 2-bytes symbol, if second character is ok */
      if (check_multibyte_characters(cursor + 1,to_end-1,1)) {
        return 2;
      } else {
        return -1;
      }
    } else if ((b & 0xf0) == 0xe0) {
      /* 3 bytes symbol, if 2nd and 3rd characters are ok */
      if (check_multibyte_characters(cursor+1,to_end-1,2)) {
        return 3;
      } else {
        return -1;
      }
    } else if ((b & 0xf8) == 0xf0) {
      /* 4 bytes symbol, if 2nd, 3rd and 4th characters are ok */
      if (check_multibyte_characters(cursor+1,to_end-1,3)) {
        return 4;
      } else {
        return -1;
      }
    } else {
      /* Invalid character, just escape */
      return -1;
    }
}

size_t append_escaped(struct printbuf *buffer,const char *string,size_t string_len)
{
  assert(buffer);
  assert(string);

  static const char *percent         = "%";
  static const char *to_escape_chars = "\"\\/\b\f\n\r\t";
  static const char *escaped_chars   = "\"\\/bfnrt";

  const size_t start_bpos = buffer->bpos;
  unsigned i=0;
  while(i<string_len)
  {
    char *escaped = NULL;
    /* Check against UTF-8 validation */
    const int utf8_length = valid_utf8_char(string + i,string_len - i);
    if(utf8_length < 0) {
      /* Invalid character, better print percent notation */
      printbuf_memappend_fast(buffer,percent,strlen(percent));
      printbuf_memappend_fast_n16(buffer,string[i]);
      ++i;
    } else if (utf8_length == 1 &&
        (escaped = memchr(to_escape_chars,string[i],strlen(to_escape_chars)))) {
      /* Need to escape JSON character */
      const size_t escaped_offset = escaped - to_escape_chars;
      printbuf_memappend_fast(buffer,"\\",1);
      printbuf_memappend_fast(buffer,&escaped_chars[escaped_offset],1);
      ++i;
    } else {
      /* Normal character, we are safe */
      printbuf_memappend_fast(buffer,&string[i],(size_t)utf8_length);
      i += utf8_length;
    }
  }

  return buffer->bpos - start_bpos;
}

size_t printNetflowRecordWithTemplate(struct printbuf * kafka_line_buffer, const V9V10TemplateElementId * templateElement, const char * buffer,const size_t real_field_len, const size_t real_field_len_offset, struct flowCache *flowCache)
{
  #ifdef CISCO_URL
  #if 1
  //static __thread char url[2048] = {'\0'};
  //static __thread int social_user_printed = 0; // useful for coordinate host+url and referer social user printing
  #endif
  #endif
  const int start_bpos = kafka_line_buffer->bpos;
  int value_ret=0;
  if(0!=strcmp(kafka_line_buffer->buf,"{")){
    printbuf_memappend_fast(kafka_line_buffer,",",strlen(","));
  }
  printbuf_memappend_fast(kafka_line_buffer,"\"",strlen("\""));
  printbuf_memappend_fast(kafka_line_buffer,templateElement->jsonElementName,
    strlen(templateElement->jsonElementName));
  printbuf_memappend_fast(kafka_line_buffer,"\":",strlen("\":"));

  if (templateElement->quote) {
    printbuf_memappend_fast(kafka_line_buffer,"\"",strlen("\""));
  }

  if(likely(NULL!=templateElement->export_fn)){
    value_ret = templateElement->export_fn(kafka_line_buffer,buffer,real_field_len, real_field_len_offset, flowCache); // at the moment
  }


  {
    // @TODO Move all this .
    const size_t bufsize = 1024;
    char buf[bufsize];
    buf[0] = '\0';

    switch(templateElement->templateElementId)
    {
      case CISCO_HTTP_SOCIAL_MEDIA_YT:
      case CISCO_HTTP_SOCIAL_USER_FB:
      case CISCO_HTTP_SOCIAL_MEDIA_TT:
      case CISCO_HTTP_SOCIAL_USER_TT:
      case CISCO_HTTP_SOCIAL_MEDIA_IG:
      case CISCO_HTTP_USER_AGENT_OS:
        if(real_field_len < 6)
          break;
        snprintf(buf,min(sizeof(buf),(unsigned) real_field_len-6+1),"%s",buffer+real_field_len_offset+6);
        break;
      default:
        // Do nothing
        break;
    };

    /// @TODO send all this to template system
    if(NULL==templateElement->export_fn) switch(templateElement->templateElementId)
    {
#ifdef HAVE_CISCO_URL
      case CISCO_URL:
        // do nothing. subtask will do.
        break;

      case CISCO_HTTP_HOST_L1:
      case CISCO_HTTP_REFERER_L1:
      if(real_field_len > 6){
        char * referer = malloc(sizeof(char)*(real_field_len -6 + 1));
        snprintf(referer,real_field_len-6,"%s",buffer+real_field_len_offset+6);
        size_t domain_len;
        const char *l1_domain = rb_l1_domain(referer,&domain_len, readOnlyGlobals.rb_databases.domains_name_as_list);
        if(l1_domain)
          value_ret = append_escaped(kafka_line_buffer,l1_domain,domain_len);
        free(referer);
      }
      break;

#if 0 /* SOCIAL_MEDIA */
      case CISCO_HTTP_USER_AGENT_OS:
      {
        rb_keyval_list_t * iter;
        for(iter=readOnlyGlobals.rb_databases.os_name_as_list;value_ret==0 && iter;iter=iter->next)
        {
          if(strcasestr(buf,iter->val))
            value_ret = sprintbuf(kafka_line_buffer, "%s", iter->key);
        }
      }
      break;
      case CISCO_HTTP_SOCIAL_USER_FB:
        if(unlikely(strstr(buf,"akamaihd.net") || strstr(buf,"ak.fbcdn.net"))){
          size_t phid_len;
          const char * phid = extract_fb_photo_id(url,strlen(url),
                                                 buf,
                                                 &phid_len);
          if(phid)
          {
            value_ret = sprintbuf(kafka_line_buffer,"http://www.facebook.com/profile.php?id=");
            printbuf_memappend_fast(kafka_line_buffer,phid,phid_len-1);
            value_ret += phid_len - 1;
            social_user_printed = 1;
          }else
            return(0);
        }
        break;
      case CISCO_HTTP_SOCIAL_MEDIA_TT:
        if(unlikely(strstr(buf,"twitter.com") &&
                         strstr(url,"status")))
        {
          value_ret = sprintbuf(kafka_line_buffer,"%s%s",buf,url);
        }
        break;
      case CISCO_HTTP_SOCIAL_USER_TT:
        {
          // Format: *twitter.com/USER/status/###
          char * twitter_com_string = strstr(buf,"twitter.com");
          char * status_string      = strstr(url,"status");
          if(unlikely(twitter_com_string && status_string))
          {
            value_ret = sprintbuf(kafka_line_buffer,twitter_com_string + strlen("twitter.com"),status_string - twitter_com_string);
          }

          /* Format: *api.twitter.com*?screen_name=USER* */
          if(real_field_len>6)
          {
            const struct counted_string host = {buffer+real_field_len_offset+6,real_field_len-6};
            const struct counted_string counted_url  = {url,strlen(url)};

            const struct counted_string tw_user = extract_tw_user(&counted_url,&host);
            if(tw_user.string)
            {
              const size_t initial_size = kafka_line_buffer->bpos;
              printbuf_memappend_fast(kafka_line_buffer,"https://twitter.com/",strlen("https://twitter.com/"));
              printbuf_memappend_fast(kafka_line_buffer,tw_user.string,tw_user.len);
              value_ret = kafka_line_buffer->bpos - initial_size;
              //sprintf(kafka_line_buffer,tw_user.len+1,"%s",tw_user.string);
            }
          }
        }
        if(unlikely(strstr(buf,"twitter.com") && strstr(url,"status")))
        {
          value_ret = print_twitter_user(kafka_line_buffer,buf);
        }
        break;

      case CISCO_HTTP_SOCIAL_USER_YT:
        {
          /* Format: gdata.youtube.com/feeds/api/users/USERNAME */
          if(real_field_len > 6)
          {
            const struct counted_string host = {buffer+real_field_len_offset+6,real_field_len-6};
            const struct counted_string counted_url  = {url,strlen(url)};

            const struct counted_string yt_user = extract_yt_user(&host,&counted_url);
            if(yt_user.len > 0 && yt_user.string)
            {
              const size_t initial_size = kafka_line_buffer->bpos;
              printbuf_memappend_fast(kafka_line_buffer,"https://www.youtube.com/user/",strlen("https://www.youtube.com/user/"));
              printbuf_memappend_fast(kafka_line_buffer,yt_user.string,yt_user.len);
              value_ret = kafka_line_buffer->bpos - initial_size;
            }
          }
        }
        break;

      case CISCO_HTTP_SOCIAL_USER_DROPBOX:
      {
        if(real_field_len>6)
        {
          const struct counted_string host = {buffer+real_field_len_offset+6,real_field_len-6};
          const struct counted_string counted_url  = {url,strlen(url)};

          const struct counted_string dropbox_user = extract_dropbox_user(&host,&counted_url);
          if(dropbox_user.len > 0 && dropbox_user.string)
          {
            const size_t initial_size = kafka_line_buffer->bpos;
            printbuf_memappend_fast(kafka_line_buffer,"Dropbox id: ",strlen("Dropbox id:"));
            printbuf_memappend_fast(kafka_line_buffer,dropbox_user.string,dropbox_user.len);
            value_ret = kafka_line_buffer->bpos - initial_size;
          }
        }
      }
      case CISCO_HTTP_SOCIAL_USER_YT_REFERER:
        {
          /* Format: gdata.youtube.com/feeds/api/users/USERNAME */
          if(real_field_len > 6)
          {
            const struct counted_string referer = {buffer+real_field_len_offset+6,real_field_len-6};

            const struct counted_string yt_user = extract_yt_user_referer(&referer);
            if(yt_user.len > 0 && yt_user.string)
            {
              const size_t initial_size = kafka_line_buffer->bpos;
              printbuf_memappend_fast(kafka_line_buffer,"https://www.youtube.com/user/",strlen("https://www.youtube.com/user/"));
              printbuf_memappend_fast(kafka_line_buffer,yt_user.string,yt_user.len);
              value_ret = kafka_line_buffer->bpos - initial_size;
            }
          }
        }
        break;
      case CISCO_HTTP_SOCIAL_MEDIA_IG:
        if(unlikely(NULL!=strstr(buf,"instagram")) && strstr(buf,"distilleryimage"))
        {
          value_ret = sprintbuf(kafka_line_buffer,"%s%s",buf,url);
        }
        break;
      case CISCO_HTTP_SOCIAL_MEDIA_YT:
        if(unlikely(NULL!=strstr(buf,"youtube") && (NULL!=strstr(url,"watch") || NULL!=strstr(url,"embed"))))
        {
          value_ret = sprintbuf(kafka_line_buffer,"%s%s",buf,url);
        }
        break;
#endif
#endif
      default:
        if (NULL == templateElement->export_fn &&
                                        NULL == templateElement->postTemplate &&
                                        readOnlyGlobals.enable_debug) {
          traceEvent(TRACE_ERROR, "Unknown template id %s(%d).\n",
            templateElement->jsonElementName,
            templateElement->templateElementId);
        }
        break;
    };

    if(value_ret < 0) /* Error adding */
    {
      // traceEvent(TRACE_ERROR, "Cannot add value to kafka buffer.\n");
    }
    else if(value_ret > 0) /* Some added */
    {
      if(templateElement->quote)
      {
        value_ret+=2;
        printbuf_memappend_fast(kafka_line_buffer,"\"",strlen("\""));
      }
    }
    else /*if(value_ret == 0)*/
    {
      kafka_line_buffer->bpos = start_bpos;
      kafka_line_buffer->buf[kafka_line_buffer->bpos] = '\0';
    }

    int i;
    for(i=0; templateElement->postTemplate != NULL
                            && templateElement->postTemplate[i] != NULL; ++i) {
          printNetflowRecordWithTemplate(kafka_line_buffer,
            templateElement->postTemplate[i], buffer, real_field_len,
            real_field_len_offset, flowCache);
    }

    switch(templateElement->templateElementId) /* See if we can extract more information about the field */
    {
      // @TODO delete value_ret, not needed anymore.
      #define print_if_template_valid(value_ret,template_elm)                                                            \
      if(template_elm){                                                                                                  \
        const int start_bpos = kafka_line_buffer->bpos;                                                                  \
        const int ret = printNetflowRecordWithTemplate(kafka_line_buffer,template_elm,buffer,real_field_len,real_field_len_offset,flowCache); \
        if(0==ret){                                                                                                      \
          kafka_line_buffer->bpos = start_bpos;                                                                          \
          kafka_line_buffer->buf[kafka_line_buffer->bpos] = '\0';                                                        \
        }else{                                                                                                           \
          value_ret+=ret;                                                                                                \
        }                                                                                                                \
      }

      case CISCO_URL:
        switch(buffer[real_field_len_offset+5]){
          case 1:
            //if(real_field_len>6 && buffer)
            //  snprintf(url,min(sizeof(url),(unsigned)real_field_len-6+1),"%s",buffer+real_field_len_offset+6);
            break;
          case 2:
            //print_if_template_valid(value_ret,readOnlyGlobals.rb_cached_templates.http_host_l1_template);
            #if 1 /* MEDIA */
            if(real_field_len>6)
            {
              //social_user_printed = 0; // <- It cannot be printed here.
              //print_if_template_valid(value_ret,readOnlyGlobals.rb_cached_templates.http_social_media_tt_template);
              //print_if_template_valid(value_ret,readOnlyGlobals.rb_cached_templates.http_social_user_fb_template);
              //print_if_template_valid(value_ret,readOnlyGlobals.rb_cached_templates.http_social_user_tt_template);
              //print_if_template_valid(value_ret,readOnlyGlobals.rb_cached_templates.http_social_user_yt_template);
              //print_if_template_valid(value_ret,readOnlyGlobals.rb_cached_templates.http_social_user_dropbox);
              //print_if_template_valid(value_ret,readOnlyGlobals.rb_cached_templates.http_social_media_ig_template);
              //print_if_template_valid(value_ret,readOnlyGlobals.rb_cached_templates.http_social_media_yt_template);
            }
            //url[0]='\0';
            break;
          case 3:
            // print_if_template_valid(value_ret,readOnlyGlobals.rb_cached_templates.http_user_agent_template);

            break;
          case 4:
            // print_if_template_valid(value_ret,readOnlyGlobals.rb_cached_templates.http_referer_template);
            //if(!social_user_printed)
            //  print_if_template_valid(value_ret,readOnlyGlobals.rb_cached_templates.http_social_user_yt_referer);
            #endif
            break;
          default:
            // Do nothing
            break;
        }
        break;
        default:
          // Do nothing
          break;
    };

  } /* end value print if no error */
  return value_ret;
}

/* ****************************************************** */

/* Same as msTimeDiff with float */
float timevalDiff(struct timeval *end, struct timeval *begin) {
  if((end->tv_sec == 0) && (end->tv_usec == 0))
    return(0);
  else {
    float f = (end->tv_sec-begin->tv_sec)*1000+((float)(end->tv_usec-begin->tv_usec))/(float)1000;

    return((f < 0) ? 0 : f);
  }
}

/* ****************************************************** */

uint32_t msTimeDiff(struct timeval *end, struct timeval *begin) {
  return((uint32_t)timevalDiff(end, begin));
}

/* ******************************************* */

unsigned int ntop_sleep(unsigned int secs) {
  unsigned int unsleptTime = secs, rest;

  sigset_t sigset, oldset;

  sigfillset(&sigset);
  pthread_sigmask(SIG_BLOCK, &sigset, &oldset);

  //   traceEvent(TRACE_NORMAL, "%s(%d)", __FUNCTION__, secs);

  while((rest = sleep(unsleptTime)) > 0)
    unsleptTime = rest;

  pthread_sigmask(SIG_SETMASK, &oldset, NULL);

  return(secs);
}

/* ******************************************* */

static void detachFromTerminal(int doChdir) {
  if(doChdir) {
    int rc = chdir("/");
    if(rc != 0) traceEvent(TRACE_ERROR, "Error while moving to / directory");
  }

  setsid();  /* detach from the terminal */

  fclose(stdin);
  fclose(stdout);
  /* fclose(stderr); */

  /*
   * clear any inherited file mode creation mask
   */
  umask (0);

  /*
   * Use line buffered stdout
   */
  /* setlinebuf (stdout); */
  setvbuf(stdout, (char *)NULL, _IOLBF, 0);
}

/* **************************************** */

void daemonize(void) {
  int childpid;

  signal(SIGHUP, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);

  if((childpid = fork()) < 0)
    traceEvent(TRACE_ERROR, "INIT: Occurred while daemonizing (errno=%d)", errno);
  else {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "DEBUG: after fork() in %s (%d)",
	       childpid ? "parent" : "child", childpid);
#endif
    if(!childpid) { /* child */
      traceEvent(TRACE_INFO, "INIT: Bye bye: I'm becoming a daemon...");
      detachFromTerminal(1);
    } else { /* father */
      traceEvent(TRACE_INFO, "INIT: Parent process is exiting (this is normal)");
      exit(0);
    }
  }
}

/* ****************************************

   Address management

   **************************************** */

// Simulates << over ipv6 addr
static void operator_ltlt(char bits[16]) {
  uint64_t *_bits=(uint64_t *)bits;

  if(_bits[1] == 0)
    /* Lower half empty */
    _bits[0] = ntohll((htonll(_bits[0])<<1));
  else
    _bits[1] = ntohll((htonll(_bits[1])<<1));
}

static int int2bits(char bits[16],int number) {
  int i;
  int _bits = number;

  // @TODO memset(bits,0xFF,sizeof(bits));
  for(i=0;i<16;++i)
    bits[i]=0xff;

  if((number > 128) || (number < 0))
    return(CONST_INVALIDNETMASK);
  else {
    while (number < 128){
      operator_ltlt(bits);
      number++;
    }
  }

  return _bits;
}

/* ********************** */

static int dotted2bits(char bits[16],const char *mask,int ipv4) {
  int num;

  int fields_num = sscanf(mask, "%d",&num);
  if(fields_num == 1)
    {
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: dotted2bits (%s) = %d", mask, fields[0]);
#endif

      return int2bits (bits,ipv4 ? num + 128-32 : num);
    }
  return CONST_INVALIDNETMASK;
}

/* ********************** */

int parseAddress(char *address, netAddress_t *netaddress) {
  int ipv6_pton_rc, ipv4_pton_rc=0;
  union {
    struct in6_addr in6;
    struct in_addr in4;
  } buf;
  char str[INET6_ADDRSTRLEN];
  int bits = CONST_INVALIDNETMASK;

  char *mask = strchr(address, '/');

  if(mask == NULL){
    int2bits(netaddress->networkMask,128);
    bits = 128;
  }
  else {
    mask[0] = '\0';
    mask++;
  }

  // Try to parse as ipv6
  ipv6_pton_rc = inet_pton(AF_INET6, address, &buf.in6);
  if(ipv6_pton_rc != 1){
    ipv4_pton_rc = inet_pton(AF_INET, address, &buf.in4);
    if(ipv4_pton_rc != 1) {
      traceEvent(TRACE_ERROR,"Can't parse IP %s",address);
    }
  }

  if(mask) {
    bits = dotted2bits (netaddress->networkMask,mask,ipv4_pton_rc);
  }

  if(bits == CONST_INVALIDNETMASK) {
    traceEvent(TRACE_ERROR,"Can't parse IP %s",address);
    return -1;
  }



  if(ipv6_pton_rc == 1) {
    memcpy(netaddress->network,buf.in6.s6_addr,
        sizeof(netaddress->network));
  } else if(ipv4_pton_rc == 1) {
    netaddress->network[0] = 0;
    netaddress->network[1] = 0;
    netaddress->network[2] = 0;
    netaddress->network[3] = 0;
    netaddress->network[4] = 0;
    netaddress->network[5] = 0;
    netaddress->network[6] = 0;
    netaddress->network[7] = 0;
    netaddress->network[8] = 0;
    netaddress->network[9] = 0;
    netaddress->network[10] = 0xFF;
    netaddress->network[11] = 0xFF;
    netaddress->network[12] = ((buf.in4.s_addr & 0x000000FF));
    netaddress->network[13] = ((buf.in4.s_addr & 0x0000FF00) >> 8);
    netaddress->network[14] = ((buf.in4.s_addr & 0x00FF0000) >> 16);
    netaddress->network[15] = ((buf.in4.s_addr & 0xFF000000) >> 24);
  }

  const char *ntop_rc = ipv6_pton_rc == 1 ?
        inet_ntop(AF_INET6, &buf.in6, str, INET6_ADDRSTRLEN) :
        inet_ntop(AF_INET, &buf.in4, str, INET6_ADDRSTRLEN);

  if(ntop_rc == NULL) {
    traceEvent(TRACE_ERROR,"Can't parse IP %s",address);
    return -1;
  }

  traceEvent(TRACE_INFO, "Adding %s/%d to the local network list",
	     ntop_rc, bits);

  return 0;
}

/* ********************** */

//#define DEBUG
#undef DEBUG

/* Utility function */
uint32_t str2addr(char *address) {
  int a, b, c, d;

  if(sscanf(address, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
    return(0);
  } else
    return(((a & 0xff) << 24) + ((b & 0xff) << 16) + ((c & 0xff) << 8) + (d & 0xff));
}

/* ************************************************ */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const uint8_t *ep, char *buf) {
  uint i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

/* ****************************************** */

/*
  UNIX was not designed to stop you from doing stupid things, because that
  would also stop you from doing clever things.
  -- Doug Gwyn
*/
void maximize_socket_buffer(int sock_fd, int buf_type) {
  int i, rcv_buffsize_base, rcv_buffsize, max_buf_size = 1024 * 2 * 1024 /* 2 MB */, debug = 0;
  socklen_t len = sizeof(rcv_buffsize_base);

  if(getsockopt(sock_fd, SOL_SOCKET, buf_type, &rcv_buffsize_base, &len) < 0) {
    traceEvent(TRACE_ERROR, "Unable to read socket receiver buffer size [%s]",
	       strerror(errno));
    return;
  } else {
    if(debug) traceEvent(TRACE_INFO, "Default socket %s buffer size is %d",
			 buf_type == SO_RCVBUF ? "receive" : "send",
			 rcv_buffsize_base);
  }

  for(i=2;; i++) {
    rcv_buffsize = i * rcv_buffsize_base;
    if(rcv_buffsize > max_buf_size) break;

    if(setsockopt(sock_fd, SOL_SOCKET, buf_type, &rcv_buffsize, sizeof(rcv_buffsize)) < 0) {
      if(debug) traceEvent(TRACE_ERROR, "Unable to set socket %s buffer size [%s]",
			   buf_type == SO_RCVBUF ? "receive" : "send",
			   strerror(errno));
      break;
    } else
      if(debug) traceEvent(TRACE_INFO, "%s socket buffer size set %d",
			   buf_type == SO_RCVBUF ? "Receive" : "Send",
			   rcv_buffsize);
  }
}

/* ****************************************** */

#ifdef linux

void setCpuAffinity(char *cpuId) {
  pid_t p = 0; /* current process */
  int ret, num = 0;
  cpu_set_t cpu_set;
  int numCpus = sysconf(_SC_NPROCESSORS_CONF);
  char *strtokState, *cpu, _cpuId[256] = { 0 };

  if(cpuId == NULL)
    return; /* No affinity */

  traceEvent(TRACE_INFO, "This computer has %d processor(s)\n", numCpus);

  CPU_ZERO(&cpu_set);

  cpu = strtok_r(cpuId, ",", &strtokState);
  while(cpu != NULL) {
    int id = atoi(cpu);

    if((id >= numCpus) || (id < 0)) {
      traceEvent(TRACE_ERROR, "Skept CPU id %d as you have %d available CPU(s) [0..%d]", id, numCpus, numCpus-1);
    } else {
      CPU_SET(id, &cpu_set), num++;
      traceEvent(TRACE_INFO, "Adding CPU %d to the CPU affinity set", id);
      snprintf(&_cpuId[strlen(_cpuId)], sizeof(_cpuId)-strlen(_cpuId)-1, "%s%d", (_cpuId[0] != '\0') ? "," : "", id);
    }

    cpu = strtok_r(NULL, ",", &strtokState);
  }

  if(num == 0) {
    traceEvent(TRACE_WARNING, "No valid CPU id has been selected: skipping CPU affinity set");
    return;
  }

  ret = sched_setaffinity(p, sizeof(cpu_set_t), &cpu_set);

  if(ret == 0) {
    traceEvent(TRACE_NORMAL, "CPU affinity successfully set to %s", _cpuId);
  } else {
    traceEvent(TRACE_ERROR, "Unable to set CPU affinity to %s [ret: %d]",
	       _cpuId, ret);
  }
}

/* ******************************************* */

#endif

/* ******************************************* */

void dropPrivileges(void) {
  struct passwd *pw = NULL;

  if(readOnlyGlobals.do_not_drop_privileges) return;

#ifdef HAVE_NETFILTER
  if(readOnlyGlobals.nf.fd >= 0) {
    traceEvent(TRACE_WARNING, "Don't dropping privileges (required by NetFilter)");
    return;
  }
#endif

  if(getgid() && getuid()) {
    traceEvent(TRACE_NORMAL, "Privileges are not dropped as we're not superuser");
    return;
  }

  pw = getpwnam(readOnlyGlobals.unprivilegedUser);
  /* if(pw == NULL) pw = getpwnam(username = "anonymous"); */

  if(pw != NULL) {
    /* Change owner to pid file */
    if(readOnlyGlobals.pidPath) {
      int changeLogOwner = chown (readOnlyGlobals.pidPath, pw->pw_uid, pw->pw_gid);
      if(changeLogOwner != 0)
	traceEvent(TRACE_ERROR, "Unable to change owner to PID in file %s",
		 readOnlyGlobals.pidPath);
    }

    /* Drop privileges */
    if((setgid(pw->pw_gid) != 0) || (setuid(pw->pw_uid) != 0)) {
      traceEvent(TRACE_WARNING, "Unable to drop privileges [%s]",
		 strerror(errno));
    } else
      traceEvent(TRACE_NORMAL, "nProbe changed user to '%s'",
		 readOnlyGlobals.unprivilegedUser);
  } else {
    traceEvent(TRACE_WARNING, "Unable to locate user %s",
	       readOnlyGlobals.unprivilegedUser);
  }

  umask(0);
}

/* ******************************************* */

static char* LogEventSeverity2Str(LogEventSeverity event_severity) {
 switch(event_severity) {
 case severity_error:   return("ERROR");
 case severity_warning: return("WARN");
 case severity_info:    return("INFO");
 default:               return("???");
 }
}

/* ******************************************* */

static char* LogEventType2Str(LogEventType event_type) {
  switch(event_type) {
  case probe_started:              return("F2K_START");
  case probe_stopped:              return("F2K_STOP");
  case packet_drop:                return("CAPTURE_DROP");
  case flow_export_error:          return("FLOW_EXPORT_ERROR");
  case collector_connection_error: return("COLLECTOR_CONNECTION_ERROR");
  case collector_connected:        return("CONNECTED_TO_COLLECTOR");
  case collector_disconnected:     return("DISCONNECTED_FROM_COLLECTOR");
  case collector_too_slow:         return("COLLECTOR_TOO_SLOW");
  default:                         return("???");
  }
}

/* ******************************************* */

void dumpLogEvent(LogEventType event_type, LogEventSeverity severity, char *message) {
  FILE *fd;
  time_t theTime;
  char theDate[32];
  static int skipDump = 0;

  if(readOnlyGlobals.eventLogPath == NULL) return;

  fd = fopen(readOnlyGlobals.eventLogPath, "a");
  if(fd == NULL) {
    if(!skipDump) {
      traceEvent(TRACE_WARNING, "Unable to append event on file %s",
		 readOnlyGlobals.eventLogPath);
      skipDump = 1;
    }

    return;
  } else
    skipDump = 0;

  // theTime = time(NULL);
  strftime(theDate, sizeof(theDate), "%d/%b/%Y %H:%M:%S", localtime(&theTime));

  fprintf(fd, "%s\t%s\t%s\t\t%s\n", theDate,
	  LogEventSeverity2Str(severity),
	  LogEventType2Str(event_type), message ? message : "");
  fclose(fd);
}

/* ****************************************************** */

uint64_t to_msec(struct timeval *tv) {
  uint64_t val = (uint64_t)tv->tv_sec * 1000;

  val += (uint64_t)tv->tv_usec/1000;

  return(val);
}

/* ****************************************************** */

void setThreadAffinity(uint core_id) {
#ifdef HAVE_PTHREAD_SET_AFFINITY
  if((getNumCores() > 1) && (readOnlyGlobals.numProcessThreads > 1)) {
    /* Bind this thread to a specific core */
    int rc;
#ifdef __NetBSD__
    cpuset_t *cset;
    cpuid_t ci;

    cset = cpuset_create();
    if (cset == NULL) {
      err(EXIT_FAILURE, "cpuset_create");
    }

    ci = core_id;
    cpuset_set(ci, cset);
    rc = pthread_setaffinity_np(pthread_self(), cpuset_size(cset), cset);
#else
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),  &cpuset);
#endif

    if(rc != 0) {
      traceEvent(TRACE_ERROR, "Error while binding to core %ld: errno=%i\n",
		 core_id, rc);
    } else {
      traceEvent(TRACE_INFO, "Bound thread to core %lu/%u\n", core_id, getNumCores());
    }
  }
#endif
}

/* ****************************************************** */

#ifdef HAVE_PTHREAD_SET_AFFINITY

static size_t getNumCores(void) {
#ifdef linux
  return(sysconf(_SC_NPROCESSORS_CONF));
#else
  return(ACT_NUM_PCAP_THREADS);
#endif
}

#endif

/* *********************************************** */

int bindthread2core(pthread_t thread_id, int core_id) {
#ifdef HAVE_PTHREAD_SET_AFFINITY
  cpu_set_t cpuset;
  int s;

  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  if((s = pthread_setaffinity_np(thread_id, sizeof(cpu_set_t), &cpuset)) != 0) {
    traceEvent(TRACE_WARNING, "Error while binding to core %u: errno=%i\n", core_id, s);
    return(-1);
  } else {
    return(0);
  }
#else
  traceEvent(TRACE_WARNING, "Your system lacks of pthread_setaffinity_np() (not core binding)\n");
  return(0);
#endif
}

/* ****************************************************** */
/*                     ENEO STUFFS                        */
/* ****************************************************** */

void check_if_reload(/*const int templateElementId,*/struct rb_databases * rb_databases)
{
  assert(rb_databases);

  if(unlikely(rb_databases->reload_hosts_database || rb_databases->reload_nets_database))
  {
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_NORMAL,"reloading hosts_database");
    pthread_rwlock_wrlock(&rb_databases->mutex);
    freeHostsList(rb_databases->ip_name_as_list);
    freeHostsList(rb_databases->nets_name_as_list);
    rb_databases->ip_name_as_list = rb_databases->nets_name_as_list = NULL;

    parseHostsList(rb_databases->hosts_database_path);
    rb_databases->reload_hosts_database = rb_databases->reload_nets_database = 0;
    pthread_rwlock_unlock(&rb_databases->mutex);
  }
  if(unlikely(rb_databases->reload_vlans_database))
  {
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_NORMAL,"reloading vlans_database");
    pthread_rwlock_wrlock(&rb_databases->mutex);
    unload_vlan_mapping();
    load_vlan_mapping();
    rb_databases->reload_vlans_database = 0;
    pthread_rwlock_unlock(&rb_databases->mutex);
  }

  if(unlikely(rb_databases->reload_apps_database))
  {
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_NORMAL,"reloading apps_database");
    pthread_rwlock_wrlock(&rb_databases->mutex);
    if(rb_databases->apps_name_as_list)
      deleteNumNameAssocTree(rb_databases->apps_name_as_list);
    rb_databases->apps_name_as_list = newNumNameAssocTree();
    char buf[1024];
    snprintf(buf,1024,"%s%s",rb_databases->hosts_database_path,"/applications");
    parseAppList(buf);
    rb_databases->reload_apps_database = 0;
    pthread_rwlock_unlock(&rb_databases->mutex);
  }

  if(unlikely(rb_databases->reload_engines_database))
  {
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_NORMAL,"reloading engines_database");
    pthread_rwlock_wrlock(&rb_databases->mutex);
    freeNumList(rb_databases->engines_name_as_list);
    char buf[1024];
    snprintf(buf,1024,"%s%s",rb_databases->hosts_database_path,"/engines");
    parseEngineList(buf);
    rb_databases->reload_engines_database = 0;
    pthread_rwlock_unlock(&rb_databases->mutex);
  }

  if(unlikely(rb_databases->reload_domains_database))
  {
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_NORMAL,"reloading domains_database");
    pthread_rwlock_wrlock(&rb_databases->mutex);
    freeNumList(rb_databases->domains_name_as_list);
    char buf[1024];
    snprintf(buf,1024,"%s%s",rb_databases->hosts_database_path,"/http_domains");
    parseHTTPDomainsList(buf);
    rb_databases->reload_domains_database = 0;

    freeOSList(&rb_databases->domainalias_database);
    snprintf(buf,1024,"%s%s",rb_databases->hosts_database_path,"/http_host_l1_alias");
    parseCharCharList_File(&rb_databases->domainalias_database,buf);
    rb_databases->reload_domainalias_database = 0;
    pthread_rwlock_unlock(&rb_databases->mutex);
  }

  if(unlikely(rb_databases->reload_os_database))
  {
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_NORMAL,"reloading os_database");
    pthread_rwlock_wrlock(&rb_databases->mutex);
    freeOSList(&rb_databases->os_name_as_list);
    char buf[1024];
    snprintf(buf,1024,"%s%s",rb_databases->hosts_database_path,"/os");
    parseCharCharList_File(&rb_databases->os_name_as_list,buf);
    rb_databases->reload_os_database = 0;
    pthread_rwlock_unlock(&rb_databases->mutex);
  }

  if(unlikely(rb_databases->reload_macs_database))
  {
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_NORMAL,"reloading macs_database");
    pthread_rwlock_wrlock(&rb_databases->mutex);
    freeIfAddressList(&rb_databases->mac_name_database);
    char buf[1024];
    snprintf(buf,1024,"%s%s",rb_databases->hosts_database_path,"/macs");
    parseIfAddressList(buf);
    rb_databases->reload_macs_database=0;
    pthread_rwlock_unlock(&rb_databases->mutex);
  }

  if(unlikely(rb_databases->reload_macs_vendor_database))
  {
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_NORMAL,"reloading macs_vendor_database");
    pthread_rwlock_wrlock(&rb_databases->mutex);
    if(rb_databases->mac_vendor_database)
      rb_destroy_mac_vendor_db(rb_databases->mac_vendor_database);
    if(rb_databases->mac_vendor_database_path){
      rb_databases->mac_vendor_database = rb_new_mac_vendor_db(rb_databases->mac_vendor_database_path);
    }
    rb_databases->reload_macs_vendor_database = 0;
    pthread_rwlock_unlock(&rb_databases->mutex);
  }
}

int parseHostsList_File(char * filename,PARSEHOSTSLIST_ORDER order){
  char line_buffer[1024] = {'\0'};
  IPNameAssoc ** iter = NULL;
  switch(order)
  {
    case HOST_ORDER:
      iter = &readOnlyGlobals.rb_databases.ip_name_as_list;
      break;
    case NETWORK_ORDER:
      iter = &readOnlyGlobals.rb_databases.nets_name_as_list;
      break;
    case APPLICATION_ORDER:
      /* Managed later */
      break;
    case ENGINE_ORDER:
      iter = &readOnlyGlobals.rb_databases.engines_name_as_list;
      break;
    case DOMAINS_ORDER:
      iter = &readOnlyGlobals.rb_databases.domains_name_as_list;
      break;
    case IFADDR_ORDER:
      STAILQ_INIT(&readOnlyGlobals.rb_databases.mac_name_database);
      break;
    default:
      traceEvent(TRACE_ERROR, "FATAL ERROR: Not a valid order given.\n");
      exit(-1);
  };



  FILE *file = fopen(filename,"r");
  int line=1;

  if(!file){
    traceEvent(TRACE_WARNING,"Error opening file %s. Hosts/Nets identification by name"
        " will be disabled",filename);
    return 0;
  }

  while(NULL != fgets(line_buffer,1024,file)){
    if(line_buffer[0]!='#' && line_buffer[0]!='\n'){
      char *pos;
      char * tok1 = strtok_r(line_buffer," \t\n",&pos);
      char * tok2=NULL;
      if(tok1){
        tok2 = strtok_r(NULL," \t\n",&pos); // Note: domain name has it too.
        if(NULL==tok2)
        {
          traceEvent(TRACE_ERROR,"Error in %s(%d): entry without number.",filename,line);
          continue;
        }
// @TODO Change switch by callbacks
        switch(order)
        {
          case IFADDR_ORDER:
            {
              mac_addr_list_node * node = malloc(sizeof(mac_addr_list_node));
              node->name     = strdup(tok1);
              node->number_a = strdup(tok2);
              node->number_i = mac_atoi(node->number_a);
              STAILQ_INSERT_TAIL(&readOnlyGlobals.rb_databases.mac_name_database, node, next);
            }
            break;

          case APPLICATION_ORDER:
          {
            char err[1024];
            char *end=NULL;

            const long app_id = strtol(tok2,&end,10);
            if(app_id==0 && *end!='\0'){
              traceEvent(TRACE_ERROR,"No valid app id (%s).",tok2);
              continue;
            }

            const int addNum_rc = addNumNameAssocToTree(readOnlyGlobals.rb_databases.apps_name_as_list,app_id,tok1,err,sizeof(err));
            if(addNum_rc == 0){
              traceEvent(TRACE_ERROR,"Can't add app_id: %s",err);
            }
          }
          break;

          default:
            {
              *iter = calloc(1,sizeof(IPNameAssoc));
              if(NULL==*iter
                 || NULL == ((*iter)->number = strdup(tok2))
                 || NULL == ((*iter)->name = strdup(tok1))){
                traceEvent(TRACE_ERROR,"Cannot allocate hostlist node, exiting\n");
                exit(1);
              }
              switch(order)
              {
                case HOST_ORDER:
                case NETWORK_ORDER:
                  if( -1==safe_parse_address((*iter)->number,&(*iter)->number_i.net_address)){
                    traceEvent(TRACE_WARNING,"In file %s line %d: %s",filename,line,line_buffer);
                    free(*iter);
                    *iter=NULL;
                    continue; /*while*/
                  }
                  break;
                case APPLICATION_ORDER:
                case ENGINE_ORDER:
                  (*iter)->number_i.number = atoi((*iter)->number);
                  break;
                case DOMAINS_ORDER:
                  (*iter)->number_i.number = strlen((*iter)->name);
                  break;

                  default:
                    traceEvent(TRACE_ERROR, "FATAL ERROR: Not a valid order given.\n");
                    exit(-1);
              };

              iter = &(*iter)->next;
            }
        }
      }

    }
    line++;
  }

  fclose(file);
  return 1;
}

void parseHostsList(char * etc_path){
  assert(etc_path);
  size_t len_etc_path = strlen(etc_path);
  // Maximum use of buffer
  char * buf = calloc((len_etc_path + strlen("/networks") + 1),sizeof(char));
  strcpy(buf,etc_path);

  strcpy(buf+len_etc_path,"/hosts");
  parseHostsList_File(buf,HOST_ORDER);

  strcpy(buf+len_etc_path,"/networks");
  parseHostsList_File(buf,NETWORK_ORDER);

  free(buf);
}

void freeHostsList(IPNameAssoc * p_ip_name_list){
  IPNameAssoc * aux;
  while(p_ip_name_list){
    aux = p_ip_name_list->next;
    free(p_ip_name_list->name);
    free(p_ip_name_list->number);
    free(p_ip_name_list);
    p_ip_name_list=aux;
  }
}

static const char *rev_strchr(const char *str,const char *last_char,int character)
{
  const char * it = last_char;
  while(it>str && *it!=character)
    it--;
  return it;
}

/* strchr that return the last character instead of NULL if the character was not found */
static const char *strchr_or_end(const char *str,int character)
{
  const char * it = str;
  while(*it!=character && *it!='\0')
    it++;
  return it;
}

// @TODO delete this define
#define _strchr strchr_or_end

/* strchr that return the last character instead of NULL if the character was not found */
static const char *sstrchr_or_end(const struct counted_string *str,int character)
{
  const char * it = str->string;
  while(*it!=character && it - str->string < (unsigned)str->len )
    it++;
  return it;
}

// @todo clean this function
const char * rb_l1_domain(const char *url, size_t *domain_len,const NumNameAssoc *domainlist)
{
  char host[1024];
  const char * l1_domain=NULL;
  /* skipping http(s):// */
  const char * doublebar = strstr(url,"//");
  const char * real_referer = doublebar?doublebar+2 : url;

  /* searching last bar in http://page.d2.d1/ */
  const char * last_bar = _strchr(real_referer,'/');

  /* domain:80 ? */
  const char * colon = rev_strchr(real_referer,last_bar,':');
  const char * last_point = colon==real_referer ? /* No ':' found */ last_bar : colon;

  const size_t host_len = snprintf(host,last_point - real_referer,"%s",real_referer);

  if(host_len == 0)
    return NULL;

  unsigned i;
  for(i=0;i<host_len;++i)
    if(!isprint(host[i]))
      return NULL;

  {
    {
      // Searching if the string it's a IP
      struct sockaddr_in sa;
      const int result = inet_pton(AF_INET, host, &(sa.sin_addr));
      if(result!=0)
      {
        *domain_len = last_point-real_referer;
        l1_domain = real_referer;
        return l1_domain;
      }
    }

    int l1_domain_found=0;
    const char * _l1_point = last_point;
    while(!l1_domain_found)
    {
      _l1_point = rev_strchr(real_referer,_l1_point-1,'.');
      if(*_l1_point=='.') _l1_point++;

      // printf("searching %dst characters of %s\n",last_point-_l1_point,_l1_point);
      if(namenInList(_l1_point,domainlist,last_point-_l1_point-1))
      {
        if(_l1_point > real_referer)
        {
          _l1_point--; // skipping
          last_point = _l1_point;
        }
        else
          l1_domain_found=1;
      }
      else
        l1_domain_found=1;
    }


    if(l1_domain_found)
    {
      *domain_len = last_point - _l1_point;
      l1_domain = _l1_point + (*_l1_point=='.' ? 1 : 0);
    }

    // still have to check if the domain is an alias.
    if(l1_domain)
    {
      rb_keyval_list_t * iter;
      for(iter = readOnlyGlobals.rb_databases.domainalias_database; iter; iter = iter->next)
      {
        if(0==strncasecmp(iter->key,l1_domain,*domain_len))
        {
          l1_domain = iter->val;
          *domain_len = strlen(l1_domain);
        }
      }
    }
  }

#if 0
  /* searching point that starts the 2nd level domain */
  if(l2_domain)
  {
    char * _l2_point = _l1_point-1;
    while(_l2_point > real_referer && *_l2_point!=0 && *_l2_point != '.')
      _l2_point--;
    *l2_domain = _l2_point+1;
  }
#endif
  return l1_domain;
}

/* TODO Merge with parseHostList_File */
int parseCharCharList_File(rb_keyval_list_t **list, char * filename){
  char line_buffer[1024] = {'\0'};
  rb_keyval_list_t ** iter = list;//&readOnlyGlobals.os_name_as_list;

  FILE *file = fopen(filename,"r");
  int line=1;

  if(!file){
    traceEvent(TRACE_WARNING,"Error opening file %s. Hosts/Nets identification by name"
        " will be disabled",filename);
    return 0;
  }

  while(NULL != fgets(line_buffer,1024,file)){
    if(line_buffer[0]!='#' && line_buffer[0]!='\n'){
      char *pos;
      char * tok1 = strtok_r(line_buffer," \t",&pos);
      char * tok2=NULL;
      if(tok1){
        tok2 = strtok_r(NULL," \t",&pos); // Note: domain name has it too.
        if(NULL==tok2)
        {
          traceEvent(TRACE_ERROR,"Error in %s(%d): entry without number.",filename,line);
          continue;
        }
        *iter = calloc(1,sizeof(rb_keyval_list_t));
        if(NULL==*iter
           || NULL == ((*iter)->val = strdup(tok2))
           || NULL == ((*iter)->key = strdup(tok1))){
          traceEvent(TRACE_ERROR,"Cannot allocate hostlist node, exiting\n");
          exit(1);
        }

        if((*iter)->val[strlen((*iter)->val) - 1] == '\n')
          (*iter)->val[strlen((*iter)->val) - 1] = '\0';
      }

      iter = &(*iter)->next;
    }
    line++;
  }

  fclose(file);
  return 1;
}

#if 1 /* MEDIA */
const char * extract_fb_photo_id(const char *url,const size_t urllen,const char *host,size_t *size)
{
  // video not valid.
  if(strstr(host,"video"))
    return NULL;

  // finding last '/'
  //const size_t urllen = strlen(url);
  const char *first_underscore=NULL,*last_underscore=NULL;
  size_t i = urllen;
  while(i>0 && url[--i]!='/'); // searching last '/'
  const char *bar = i>0? &url[i] : NULL;
  if(bar)
  {
    while(i<urllen && url[++i]!='_');
    if(i<urllen)
      first_underscore = &url[i];

    if(first_underscore)
    {
      while(i<urllen && url[++i]!='_');
      if(i<urllen)
        last_underscore = &url[i];
    }
  }
  if(first_underscore && last_underscore)
  {
    *size = last_underscore - first_underscore;
    return ++first_underscore;
  }
  else
  {
    *size=0;
    return NULL;
  }
}

#endif

/** Separate kafka flow message in many flows, one per minute, and distributing
  the packets and octets proportionally.
 * @param  kafka_line_buffer Current string with parameters that all flows share
 * @param  first_timestamp   First timestamp of the flow
 * @param  dSwitched         Delta time of flow.
 * @param  dInterval         Maximum intervals allowed.
 * @param  max_intervals     Maximum number of intervals to split
 * @param  bytes             Total bytes
 * @param  pkts              Total packets
 * @return                   String list with all time separated flows
 * @todo This should be in collect.c
 */
struct string_list * rb_separate_long_time_flow(
  struct printbuf * kafka_line_buffer,
  uint64_t first_timestamp, uint64_t dSwitched, const uint64_t dInterval,
  const uint64_t max_intervals, uint64_t bytes, uint64_t pkts) {

  struct string_list *kafka_buffers_list = NULL;

  if(!kafka_line_buffer)
    return kafka_buffers_list;

  unsigned n_intervals_except_first = dSwitched/dInterval;
  if(n_intervals_except_first>max_intervals){
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_WARNING,
        "Too many intervals to divide (%u, max: %"PRIu64"). nIntervals set to "
        "%lu",
        n_intervals_except_first, max_intervals, max_intervals-1);
    n_intervals_except_first=max_intervals-1;
  }

  /* Avoiding flows with 0 pkts/bytes */
  if(dSwitched > 0 && dSwitched % dInterval == 0)
    dSwitched--;
  const time_t first_interval_duration  = dSwitched%dInterval;
  const double first_interval_duration_percent  = dSwitched == 0 ? 1 : (double)first_interval_duration/dSwitched;

  const uint64_t first_interval_bytes  = bytes * first_interval_duration_percent;
  const uint64_t first_interval_pkts   = pkts  * first_interval_duration_percent;

  const uint64_t packets_per_interval    = n_intervals_except_first > 0 ? (pkts - first_interval_pkts)/n_intervals_except_first : 0;
  const uint64_t bytes_per_interval      = n_intervals_except_first > 0 ? (bytes - first_interval_bytes)/n_intervals_except_first : 0;
  const uint64_t packets_per_interval_sw = htonll(packets_per_interval);
  const uint64_t bytes_per_interval_sw   = htonll(bytes_per_interval);

  const uint64_t remainder_packets = pkts - first_interval_pkts - packets_per_interval*n_intervals_except_first;
  const uint64_t remainder_bytes   = bytes - first_interval_bytes - bytes_per_interval*n_intervals_except_first;

  const uint64_t first_interval_pkts_sw  = htonll(first_interval_pkts + remainder_packets);
  const uint64_t first_interval_bytes_sw = htonll(first_interval_bytes + remainder_bytes);

  uint64_t current_timestamp_s  = first_timestamp;

  const char *last_sentmsg = NULL;
  size_t last_sentmsg_useful_bpos = 0; /* bpos of last_sentmsg before timestamp -> useful*/

  while(current_timestamp_s <= first_timestamp + dSwitched){
    struct string_list *node = calloc(1,sizeof(struct string_list));
    if(NULL==node){
      traceEvent(TRACE_ERROR,"Memory error");
      return kafka_buffers_list;
    }

    node->next = kafka_buffers_list?kafka_buffers_list:NULL;
    kafka_buffers_list = node;
    if(current_timestamp_s + dInterval > first_timestamp + dSwitched){
      /* Last interval -> We use the buffer passed and remainder byes */
      node->string = kafka_line_buffer;
      printNetflowRecordWithTemplate(node->string, TEMPLATE_OF(IN_BYTES),
        (const char *)&first_interval_bytes_sw,
        sizeof(first_interval_bytes_sw), 0, NULL);
      printNetflowRecordWithTemplate(node->string, TEMPLATE_OF(IN_PKTS),
        (const char *)&first_interval_pkts_sw,
        sizeof(first_interval_pkts_sw), 0, NULL);
    }else{
      /* Not last interval -> we need to clone the buffer */
      node->string = printbuf_new();
      if(NULL == node->string){
        /* Can't allocate string: Return, at least, previous list */
        kafka_buffers_list = node->next;
        free(node);
        return kafka_buffers_list;
      }

      if(NULL==last_sentmsg){
        /* No cached message to copy from -> need to generate the first */
        printbuf_memappend(node->string,kafka_line_buffer->buf,kafka_line_buffer->bpos);
        printNetflowRecordWithTemplate(node->string, TEMPLATE_OF(IN_BYTES),
          (const char *)&bytes_per_interval_sw,
          sizeof(bytes_per_interval_sw), 0, NULL);
        printNetflowRecordWithTemplate(node->string, TEMPLATE_OF(IN_PKTS),
          (const char *)&packets_per_interval_sw,
          sizeof(packets_per_interval_sw), 0, NULL);
        last_sentmsg = node->string->buf;
        last_sentmsg_useful_bpos = node->string->bpos;
      }else{
        /* Cached message: We could use it to waste less CPU */
        printbuf_memappend(node->string,last_sentmsg,last_sentmsg_useful_bpos);
      }
    }

    const uint64_t interval_timestamp_sw = htonll(current_timestamp_s);
    printNetflowRecordWithTemplate(node->string, TEMPLATE_OF(LAST_SWITCHED),
      (const char *)&interval_timestamp_sw, sizeof(interval_timestamp_sw),
      0, NULL);

    current_timestamp_s += dInterval;

    printbuf_memappend_fast(node->string,"}",strlen("}"));
  }/* foreach interval in nIntervals */

  return kafka_buffers_list;
}

/* ********************* Template management *********************** */

/// @TODO use serializeTemplate and deserializeTemplate
static int saveTemplateInFilef(const FlowSetV9Ipfix *template,FILE *f)
{
  if(NULL==template)
  {
    traceEvent(TRACE_ERROR,"Error: saveTemplateInFile called with template==NULL");
    return 0;
  }

  if(NULL==f)
  {
    traceEvent(TRACE_ERROR,"Error: saveTemplateInFile called with FILE *f==NULL");
    return 0;
  }

  size_t data_writed = 0;

  const V9IpfixSimpleTemplate *templateInfo = &template->templateInfo;
  data_writed = fwrite(templateInfo,sizeof(*templateInfo),1,f);
  if(data_writed != 1 || ferror(f))
  {
    traceEvent(TRACE_ERROR,"Error writing template info");
    return 0;
  }
  else
  {
    if(readOnlyGlobals.enable_debug)
    {
      char buf[1024];
      /* V9TemplateHeader */
      traceEvent(TRACE_NORMAL,"saveTemplate(): [flowsetLen=%d]",templateInfo->flowsetLen);
      /* V9TemplateDef */
      traceEvent(TRACE_NORMAL,"saveTemplate(): [templateId=%d]",templateInfo->templateId);
      traceEvent(TRACE_NORMAL,"saveTemplate(): [fieldCount=%d][scopeFieldCount=%d][v9ScopeLen=%d]",
        templateInfo->fieldCount, templateInfo->scopeFieldCount,templateInfo->v9ScopeLen);
      traceEvent(TRACE_NORMAL,"saveTemplate(): [netflow_device_ip=%s][observation_domain_id=%d]",
        _intoaV4(templateInfo->netflow_device_ip,buf,sizeof(buf)), templateInfo->observation_domain_id);
      traceEvent(TRACE_NORMAL,"saveTemplate(): [isOptionTemplate=%d]",templateInfo->isOptionTemplate);
    }
  }

  data_writed = fwrite(&template->flowLen,sizeof(template->flowLen),1,f);
  if(data_writed!= 1)
  {
    traceEvent(TRACE_ERROR,"Error writing flow length.");
    return 0;
  }
  else
  {
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_NORMAL,"saveTemplate(): [flowLen=%d]",template->flowLen);
  }

  unsigned int i;
  for(i=0;i<templateInfo->fieldCount;++i)
  {
    data_writed = fwrite(&template->fields[i].fieldId,sizeof(template->fields[i].fieldId),1,f);
    if(data_writed != 1)
    {
      traceEvent(TRACE_ERROR,"saveTemplate(): Error writing fieldId");
      return 0;
    }

    data_writed = fwrite(&template->fields[i].fieldLen,sizeof(template->fields[i].fieldLen),1,f);
    if(data_writed != 1)
    {
      traceEvent(TRACE_ERROR,"saveTemplate(): Error writing fieldLen");
      return 0;
    }

    data_writed = fwrite(&template->fields[i].isPenField,sizeof(template->fields[i].isPenField),1,f);
    if(data_writed != 1)
    {
      traceEvent(TRACE_ERROR,"saveTemplate(): Error writing isPenField");
      return 0;
    }

    if(readOnlyGlobals.enable_debug)
    {
      traceEvent(TRACE_NORMAL,"saveTemplate(): [field %d/%d][fieldId=%d][fieldLen=%d][isPenField=%d]",
        i,templateInfo->fieldCount,template->fields[i].fieldId,template->fields[i].fieldLen,template->fields[i].isPenField);
    }
  }

  return 1;
}

static V9V10TemplateField *loadTemplateFieldsFromFile(size_t fieldCount,FILE *f)
{
  V9V10TemplateField *fields = calloc(fieldCount, sizeof(V9V10TemplateField));
  if(fields == NULL) {
    traceEvent(TRACE_WARNING, "Not enough memory");
    return NULL;
  }

  unsigned int i;
  for(i=0;fields && i<fieldCount;++i)
  {
    size_t data_readed=0;

    data_readed = fread(&fields[i].fieldId,sizeof(fields[i].fieldId),1,f);
    if(data_readed != 1)
    {
      traceEvent(TRACE_ERROR,
        "loadTemplate(): [field %d/%zu] Error reading fieldId", i, fieldCount);
      free(fields); fields=NULL;
    }

    if(fields)
    {
      data_readed = fread(&fields[i].fieldLen,sizeof(fields[i].fieldLen),1,f);
      if(data_readed != 1)
      {
        traceEvent(TRACE_ERROR,
          "loadTemplate(): [field %d/%zu] Error reading fieldLen",
          i, fieldCount);
        free(fields); fields=NULL;
      }
    }

    if(fields)
    {
      data_readed = fread(&fields[i].isPenField,sizeof(fields[i].isPenField),1,f);
      if(data_readed != 1)
      {
        traceEvent(TRACE_ERROR,
          "loadTemplate(): [field %d/%zu] Error reading isPenField",
          i, fieldCount);
        free(fields); fields=NULL;
      }
    }

    if(fields)
    {
      fields[i].v9_template = find_template(fields[i].fieldId);
      if(NULL == fields[i].v9_template) {
        traceEvent(TRACE_ERROR,
          "loadTemplate(): [field %d/%zu] Cannot locate template element id=%d",
          i, fieldCount,fields[i].fieldId);
      }
    }

    if(fields && readOnlyGlobals.enable_debug)
    {
      traceEvent(TRACE_NORMAL,
        "loadTemplate(): [field %d/%zu][fieldId=%d][fieldLen=%d]"
        "[isPenField=%d]",
        i,fieldCount,fields[i].fieldId,fields[i].fieldLen,fields[i].isPenField);
    }
  }

  return fields;
}

static FlowSetV9Ipfix *loadTemplateFromFile(FILE *f)
{
  if(NULL==f)
  {
    traceEvent(TRACE_ERROR,"Error: saveTemplateInFile called with FILE *f==NULL");
    return NULL;
  }

  FlowSetV9Ipfix *template = calloc(1,sizeof(*template));
  if(NULL==template)
  {
    traceEvent(TRACE_ERROR,"Memory error");
    return NULL;
  }

  size_t data_readed = 0;

  V9IpfixSimpleTemplate *templateInfo = &template->templateInfo;
  data_readed = fread(templateInfo,sizeof(*templateInfo),1,f);
  if(data_readed != 1 || ferror(f))
  {
    traceEvent(TRACE_ERROR,"Error reading template info");
    free(template);return NULL;
  }
  else
  {
    if(readOnlyGlobals.enable_debug)
    {
      char buf[1024];
      /* V9TemplateHeader */
      traceEvent(TRACE_NORMAL,"loadTemplate(): [flowsetLen=%d]",templateInfo->flowsetLen);
      /* V9TemplateDef */
      traceEvent(TRACE_NORMAL,"loadTemplate(): [templateId=%d]",templateInfo->templateId);
      traceEvent(TRACE_NORMAL,"loadTemplate(): [fieldCount=%d][scopeFieldCount=%d][v9ScopeLen=%d]",
        templateInfo->fieldCount, templateInfo->scopeFieldCount,templateInfo->v9ScopeLen);
      traceEvent(TRACE_NORMAL,"loadTemplate(): [netflow_device_ip=%s][observation_domain_id=%d]",
        _intoaV4(templateInfo->netflow_device_ip,buf,sizeof(buf)), templateInfo->observation_domain_id);
      traceEvent(TRACE_NORMAL,"loadTemplate(): [isOptionTemplate=%d]",templateInfo->isOptionTemplate);
    }
  }

  data_readed = fread(&template->flowLen,sizeof(template->flowLen),1,f);
  if(data_readed!= 1)
  {
    traceEvent(TRACE_ERROR,"Error reading flow length.");
    free(template);return NULL;
  }
  else
  {
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_NORMAL,"loadTemplate(): [flowLen=%d]",template->flowLen);
  }

  template->fields = loadTemplateFieldsFromFile(templateInfo->fieldCount,f);
  if(NULL==template->fields)
  {
    free(template);template=NULL;
  }

  return template;
}

int saveTemplateInFile(const FlowSetV9Ipfix *template,const char *file)
{
  FILE * f = fopen(file,"w");
  if(f)
  {
    if(readOnlyGlobals.enable_debug)
    {
      char buf[1024];
      traceEvent(TRACE_NORMAL,"Saving template %d from %s to %s",
        template->templateInfo.templateId,_intoaV4(template->templateInfo.netflow_device_ip,buf,sizeof(buf)),file);
    }
    saveTemplateInFilef(template, f);
    fclose(f);
    return 1;
  }
  else
  {
    traceEvent(TRACE_ERROR,"Could not open template file %s to save",file);
  }
  return 0;
}

static FlowSetV9Ipfix *loadTemplate(const char *file)
{
  FILE * f = fopen(file,"r");
  if(f)
  {
    if(readOnlyGlobals.enable_debug)
      traceEvent(TRACE_NORMAL,"Loading template from file %s",file);

    FlowSetV9Ipfix *template = loadTemplateFromFile(f);

    if(readOnlyGlobals.enable_debug)
    {
      char buf[1024];
      traceEvent(TRACE_NORMAL,"Loaded template %d of sensor %s, from file %s",
        template->templateInfo.templateId,_intoaV4(template->templateInfo.netflow_device_ip,buf,sizeof(buf)),file);
    }

    fclose(f);
    return template;
  }
  else
  {
    traceEvent(TRACE_ERROR,"Could not open template file %s to save",file);
  }
  return NULL;
}

void saveTemplateInDatabase(FlowSetV9Ipfix *template) {
  assert(template);
  struct rb_sensors_db *db = readOnlyGlobals.rb_databases.sensors_info;
  const uint32_t netflow_device_ip = template->templateInfo.netflow_device_ip;
  const uint16_t dst_port = template->templateInfo.dst_port;
  struct sensor *sensor = get_sensor(db,netflow_device_ip,dst_port);

  if(sensor) {
    saveTemplate(sensor,template);
    rb_sensor_decref(sensor);
  } else {
    traceEvent(TRACE_ERROR,"Trying to save template in a unknown sensor");
  }
}

static int valid_template_filename(const char *fname)
{
  unsigned int i;
  const size_t fname_total_len = strlen(fname);
  if(fname_total_len < strlen(".dat"))
    return 0;
  const size_t fname_len = fname_total_len - strlen(".dat");
  for(i=0;i<fname_len;++i){
    if(!isdigit(fname[i]) && fname[i]!='_' && fname[i]!='.')
      return 0;
  }
  return 1;
}

int loadTemplates(const char * path)
{
	int templates_readed = 0;
	DIR* directory;
	char buf[1024];

  if(NULL == path || strlen(path) == 0){
    return 0;
  }

	directory = opendir(path);
	if(directory)
	{
		struct dirent *in_file = NULL;
		while((in_file = readdir(directory)))
		{
			if(NULL==in_file->d_name)
			{
				traceEvent(TRACE_WARNING,"Directory with no name");
				continue;
			}

			if(0==strcmp(in_file->d_name,"."))
				continue;
			if(0==strcmp(in_file->d_name,".."))
				continue;

      /* sanity check */
      if(!valid_template_filename(in_file->d_name))
      {
        if(readOnlyGlobals.enable_debug)
          traceEvent(TRACE_ERROR,"Not a valid filename: %s",in_file->d_name);
        continue;
      }

			snprintf(buf,1024,"%s/%s",path,in_file->d_name);

			FlowSetV9Ipfix *template=loadTemplate(buf);
			if(template)
			{
				saveTemplateInDatabase(template);
				templates_readed++;
			}
		}
	}
  closedir(directory);
	return templates_readed;
}

/* ****** */

#ifndef HAVE_STRNSTR
const char* strnstr(const char *haystack, const char *needle, size_t length)
{
    size_t needle_length = strlen(needle);
    size_t i;

    for (i = 0; i < length; i++)
    {
        if (i + needle_length > length)
        {
            return NULL;
        }

        if (strncmp(&haystack[i], needle, needle_length) == 0)
        {
            return &haystack[i];
        }
    }
    return NULL;
}
#endif

#define sstrstr(sstr,tok) strnstr(sstr->string,tok,sstr->len)

struct counted_string extract_tw_user(const struct counted_string *url, const struct counted_string *host)
{
    struct counted_string screen_name;
    memset(&screen_name,0,sizeof(screen_name));

    if(host && url)
    {
        // printf("Url len: %d\n",url->len);
        screen_name.string = strnstr(url->string,"screen_name",url->len);
        if(screen_name.string && strnstr(host->string,"api.twitter.com",host->len))
        {
            screen_name.string = screen_name.string + strlen("screen_name=");
            screen_name.len = url->len - (screen_name.string - url->string); // - strlen("screen_name=");
            // printf("screen_name_len: %d\n",screen_name.len);

            // Could be username=USER&otherthings...
            // @TODO use _sstrchr()
            const char * ampersand = strnstr(screen_name.string,"&",screen_name.len);
            if(ampersand)
            {
                // printf("Ampersand found!\n");
                screen_name.len = (ampersand - screen_name.string);
            }

            // printf("screen_name_len: %d\n",screen_name.len);
        }
        else
        {
          screen_name.string = NULL;
        }
    }

    return screen_name;
}

struct counted_string extract_yt_user(const struct counted_string *host,const struct counted_string *url)
{
  struct counted_string yt_user = {NULL,0};
  static const char searched_host[]   = "gdata.youtube.com";
  static const size_t searched_host_len = sizeof(searched_host)-1;
  static const char searched_url[]    = "/feeds/api/users/";
  static const size_t searched_url_len = sizeof(searched_url)-1;

  if( (host->len >= searched_host_len) && (url->len >= searched_url_len) )
  {
    if(memcmp(searched_host,host->string,searched_host_len) == 0
    && memcmp(searched_url ,url->string, searched_url_len ) == 0)
    {
      yt_user.string = url->string + searched_url_len;
      yt_user.len    = url->len    - searched_url_len;
      const char * question_mark = sstrchr_or_end(&yt_user,'?');
      const char * bar = sstrchr_or_end(&yt_user,'/');
      const char * end_of_user = min(question_mark,bar);
      assert(end_of_user!=NULL);
      yt_user.len    = end_of_user - yt_user.string;
    }
  }

  return yt_user;
}

struct counted_string extract_yt_user_referer(const struct counted_string *referer)
{
  struct counted_string yt_user = {NULL,0};
  const char *searched_header = "youtube.com/user/";
  const size_t searched_header_len = strlen(searched_header);
  if(referer->len > searched_header_len)
  {
    const char *header = sstrstr(referer,searched_header);
    if(header)
    {
      yt_user.string = header + searched_header_len;
      yt_user.len = referer->len - (yt_user.string - referer->string);

      const char * question_mark = sstrchr_or_end(&yt_user,'?');
      const char * bar = sstrchr_or_end(&yt_user,'/');
      const char * end_of_user = min(question_mark,bar);
      assert(end_of_user!=NULL);
      yt_user.len    = end_of_user - yt_user.string;
    }
  }
  return yt_user;
}

struct counted_string extract_dropbox_user(const struct counted_string *host,const struct counted_string *url)
{
  struct counted_string dropbox_user = {NULL,0};
  static const char searched_host[]   = "dropbox.com";
  static const size_t searched_host_len = sizeof(searched_host)-1;
  static const char token_user[]    = "user_id";
  static const size_t token_user_len = sizeof(token_user)-1;

  if( (host->len >= searched_host_len) && (url->len >= token_user_len) )
  {
    const char *valid_host = sstrstr(host,searched_host);
    const char *user_id = sstrstr(url,token_user);
    if(valid_host && user_id)
    {
      dropbox_user.string = user_id + token_user_len + strlen("=");
      dropbox_user.len    = url->len - (user_id + token_user_len + strlen("=") - url->string);
      const char * question_mark = sstrchr_or_end(&dropbox_user,'?');
      const char * bar = sstrchr_or_end(&dropbox_user,'/');
      const char * ampersand = sstrchr_or_end(&dropbox_user,'&');
      const char * end_of_user = min(question_mark,min(bar,ampersand));
      assert(end_of_user!=NULL);
      dropbox_user.len    = end_of_user - dropbox_user.string;
    }
  }

  return dropbox_user;
}

#if 0
#ifndef NDEBUG

void test_extract_yt_user()
{
  char buf[1024];
  buf[0] = '\0';

  const struct counted_string host = {"gdata.youtube.com",strlen("gdata.youtube.com")};
  const struct counted_string url1 = {"/feeds/api/users/",strlen("/feeds/api/users/")};
  const struct counted_string url2 = {"/feeds/api/users/USERNAME",strlen("/feeds/api/users/USERNAME")};
  const struct counted_string url3 = {"/feeds/api/users/USERNAME?blabla",strlen("/feeds/api/users/USERNAME?blabla")};

  struct counted_string yt_user1 = extract_yt_user(&host,&url1);
  assert(yt_user1.string==NULL || yt_user1.len == 0);

  struct counted_string yt_user2 = extract_yt_user(&host,&url2);
  assert(0 == memcmp(yt_user2.string,"USERNAME",strlen("USERNAME")));
  assert(yt_user2.len == strlen("USERNAME"));

  struct counted_string yt_user3 = extract_yt_user(&host,&url3);
  assert(0 == memcmp(yt_user3.string,"USERNAME",strlen("USERNAME")));
  assert(yt_user3.len == strlen("USERNAME"));
}

#endif
#endif

/* ****************************************************** */
/* End of ENEO stuffs                                     */
/* ****************************************************** */
