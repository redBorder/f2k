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

#include "f2k.h"
#include "export.h"
#include "template.h"

/* ********* NetFlow v9/IPFIX ***************************** */

/*
  Cisco Systems NetFlow Services Export Version 9

  http://www.faqs.org/rfcs/rfc3954.html

  IPFIX - Information Model for IP Flow Information Export
  http://www.faqs.org/rfcs/rfc5102.html

  See http://www.plixer.com/blog/tag/in_bytes/ for IN/OUT directions
*/

#define TP_INITIALIZERS {NULL}

#define CONCAT0(A,B) A##B
#define CONCAT(A,B) CONCAT0(A,B)

/*
  "Recursive" macro call
 */

#define APPLY0(t, dummy)
#define APPLY1(t, a) t(a)
#define APPLY2(t, a, b) t(a) t(b)
#define APPLY3(t, a, ...) t(a) APPLY2(t, __VA_ARGS__)
#define APPLY4(t, a, ...) t(a) APPLY3(t, __VA_ARGS__)
#define APPLY5(t, a, ...) t(a) APPLY4(t, __VA_ARGS__)

#define NUM_ARGS_H1(dummy, x5, x4, x3, x2, x1, x0, ...) x0
#define NUM_ARGS(...) NUM_ARGS_H1(dummy, ##__VA_ARGS__, 5, 4, 3, 2, 1, 0)
#define APPLY_ALL_H3(t, n, ...) APPLY##n(t, __VA_ARGS__)
#define APPLY_ALL_H2(t, n, ...) APPLY_ALL_H3(t, n, __VA_ARGS__)
#define APPLY_ALL(t, ...) APPLY_ALL_H2(t, NUM_ARGS(__VA_ARGS__), __VA_ARGS__)

/* ************************** */

// Only apply TEMPLATE_OF if provided 1 parameter. In other case, expand to
// nothing
#define T_CHILD_1(n) TEMPLATE_OF(n),
#define T_CHILD_0()
#define T_CHILD(...) CONCAT(T_CHILD_,NUM_ARGS(__VA_ARGS__))(__VA_ARGS__)

#define T_MKCHILDREN(...) (const V9V10TemplateElementId *[]) {                 \
                                          APPLY_ALL(T_CHILD, __VA_ARGS__) NULL }

const V9V10TemplateElementId ver9_templates[] = {
#define X(ENTERPRISE_ID, ID_STR, ID, JSON_QUOTE, NAME, \
                      JSON_NAME, IPFIX_NAME, DESCRIPTION, FUNCTION, CHILDREN)  \
        {                                                                      \
                .templateElementId = ID,                                       \
                .quote = JSON_QUOTE, .jsonElementName = JSON_NAME,             \
                .export_fn = FUNCTION, .postTemplate = T_MKCHILDREN(CHILDREN)  \
        },
        X_TEMPLATE_ENTITIES
#undef X
};

/* ******************************************** */

const char* getStandardFieldId(size_t id) {
  int i = 0;

  while(ver9_templates[i].jsonElementName != NULL) {
    if(ver9_templates[i].templateElementId == id)
      return(ver9_templates[i].jsonElementName);
    else
      i++;
  }

  return("");
}

/* ******************************************** */

const V9V10TemplateElementId *v5TemplateFields[] = {
  TEMPLATE_OF(IPV4_SRC_ADDR),
  TEMPLATE_OF(IPV4_DST_ADDR),
  //TEMPLATE_OF(IPV4_NEXT_HOP),
  TEMPLATE_OF(INPUT_SNMP),
  TEMPLATE_OF(OUTPUT_SNMP),
  TEMPLATE_OF(IN_PKTS),
  TEMPLATE_OF(IN_BYTES),
  TEMPLATE_OF(FIRST_SWITCHED),
  TEMPLATE_OF(LAST_SWITCHED),
  TEMPLATE_OF(SRC_TOS),
  TEMPLATE_OF(L4_SRC_PORT),
  TEMPLATE_OF(L4_DST_PORT),
  TEMPLATE_OF(TCP_FLAGS),
  TEMPLATE_OF(PROTOCOL),
  //TEMPLATE_OF(DST_AS),
  //TEMPLATE_OF(SRC_AS),
  //TEMPLATE_OF(IPV4_DST_MASK),
  //TEMPLATE_OF(IPV4_SRC_MASK),
  TEMPLATE_OF(ENGINE_TYPE),
  TEMPLATE_OF(ENGINE_ID),
  NULL,
};

char *serialize_template(const struct flowSetV9Ipfix *new_template,size_t *_new_buffer_size) {
  *_new_buffer_size = sizeof(new_template->templateInfo) + new_template->templateInfo.fieldCount * sizeof(new_template->fields[0]);
  const ssize_t newbufsize = *_new_buffer_size;
  char *buf = malloc(newbufsize);
  if(NULL == buf) {
    traceEvent(TRACE_ERROR,"Can't allocate new template buffer to serialize template");
    return NULL;
  }

  memcpy(buf,&new_template->templateInfo,sizeof(new_template->templateInfo));
  char *cursor = buf + sizeof(new_template->templateInfo);
  ssize_t i=0;
  for(i=0;i<new_template->templateInfo.fieldCount && cursor - buf < newbufsize;++i) {
    static const size_t field_size = sizeof(new_template->fields[i]);
    memcpy(cursor,&new_template->fields[i],field_size);
    ((V9V10TemplateField *)cursor)->v9_template = NULL;
    cursor += field_size;
  }

  if (i < new_template->templateInfo.fieldCount) {
    traceEvent(TRACE_ERROR, "Serialized %zu fields, expected %d", i,
                                        new_template->templateInfo.fieldCount);
  }
  if (cursor - buf < newbufsize) {
    traceEvent(TRACE_ERROR, "Serialized %zu bytes, expected %zu",
                                                        cursor-buf, newbufsize);
  }

  return buf;
}

struct flowSetV9Ipfix *deserialize_template(const char *buf, size_t bufsize) {
  const struct flowSetV9Ipfix *buf_template = (const void *)buf;
  size_t i;
  if (unlikely(bufsize < sizeof(V9IpfixSimpleTemplate) +
      buf_template->templateInfo.fieldCount * sizeof(buf_template->fields[0])))
      {
    traceEvent(TRACE_ERROR,
      "Buffer size %zu can't hold a %"PRIu16" fields template", bufsize,
      buf_template->templateInfo.fieldCount);
  }

  struct flowSetV9Ipfix *template = calloc(1, sizeof(*template) +
    buf_template->templateInfo.fieldCount * sizeof(buf_template->fields[0]));
  if (unlikely(template == NULL)) {
    traceEvent(TRACE_ERROR,"Can't allocate template");
    return NULL;
  }

  memcpy(&template->templateInfo, buf, sizeof(template->templateInfo));
  template->fields = (void *)&template[1];
  const char *cursor = buf + sizeof(template->templateInfo);
  for(i=0;
        i<template->templateInfo.fieldCount && (size_t)(cursor - buf) < bufsize;
        ++i) {
    memcpy(&template->fields[i], cursor, sizeof(template->fields[i]));
    cursor += sizeof(template->fields[i]);
  }

  if((size_t)(cursor - buf) < bufsize) {
    traceEvent(TRACE_WARNING,
      "There is still buffer to process (%zu bytes)", bufsize - (cursor - buf));
  }

  return template;
}

const V9V10TemplateElementId *find_template(const int templateElementId) {
  unsigned int all_template_cursor=0;
  while(ver9_templates[all_template_cursor].templateElementId != 0)
  {
    if(ver9_templates[all_template_cursor].templateElementId == templateElementId)
      return &ver9_templates[all_template_cursor];
    all_template_cursor++;
  }
  //assert(!*"Template not found");
  return NULL;
}
