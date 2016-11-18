
#include "f2k.h"
#include "util.c"
#include "rb_lists.c"

#if 0
/* TODO */
static void testSaveAndLoadTemplate_loadFromInvalidFile()
{
  traceEvent(TRACE_NORMAL,"Trying to read from an invalid file");

  char *fsname = strdup("invalid_fsname_XXXXXX");
  struct stat file_stats;

  do{
    const char *tmpnam_ret = tmpnam(fsname);
    assert(tmpnam_ret!=NULL);
  }while(!(stat(fsname,&file_stats) && errno==ENOENT));

  FlowSetV9Ipfix * loadTemplateFromInvalidFile_ret = loadTemplate(fsname);
  assert(loadTemplateFromInvalidFile_ret==NULL);
  free(fsname);
}

#define TEST_SAVE_AND_LOAD_TEMPLATE_EXAMPLE_IP 0x12345678L
static const uint32_t example_ip = TEST_SAVE_AND_LOAD_TEMPLATE_EXAMPLE_IP;
static const V9V10TemplateField templateFields[] =
{
  {.fieldId=8,.fieldLen=4,.isPenField=0,.v9_template=NULL},
  {.fieldId=12,.fieldLen=4,.isPenField=0,.v9_template=NULL},
  {.fieldId=60,.fieldLen=1,.isPenField=0,.v9_template=NULL},
  {.fieldId=4,.fieldLen=1,.isPenField=0,.v9_template=NULL},
  {.fieldId=56,.fieldLen=6,.isPenField=0,.v9_template=NULL},
  {.fieldId=80,.fieldLen=6,.isPenField=0,.v9_template=NULL},
  {.fieldId=136,.fieldLen=1,.isPenField=0,.v9_template=NULL},
  {.fieldId=239,.fieldLen=1,.isPenField=0,.v9_template=NULL},
  {.fieldId=81,.fieldLen=6,.isPenField=0,.v9_template=NULL},
  {.fieldId=57,.fieldLen=6,.isPenField=0,.v9_template=NULL},
  {.fieldId=61,.fieldLen=1,.isPenField=0,.v9_template=NULL},
  {.fieldId=48,.fieldLen=1,.isPenField=0,.v9_template=NULL},
  {.fieldId=95,.fieldLen=4,.isPenField=0,.v9_template=NULL},
  {.fieldId=12235,.fieldLen=65535,.isPenField=1,.v9_template=NULL},
  {.fieldId=12235,.fieldLen=65535,.isPenField=1,.v9_template=NULL},
  {.fieldId=12235,.fieldLen=65535,.isPenField=1,.v9_template=NULL},
  {.fieldId=12235,.fieldLen=65535,.isPenField=1,.v9_template=NULL},
  {.fieldId=1,.fieldLen=8,.isPenField=0,.v9_template=NULL},
  {.fieldId=2,.fieldLen=4,.isPenField=0,.v9_template=NULL},
  {.fieldId=22,.fieldLen=4,.isPenField=0,.v9_template=NULL},
  {.fieldId=21,.fieldLen=4,.isPenField=0,.v9_template=NULL},
};

static const FlowSetV9Ipfix example_template =
{
  .templateInfo = {
    .flowsetLen = 104,
    /* V9TemplateDef */
    .templateId = 264,
    .fieldCount = sizeof(templateFields)/sizeof(templateFields[0]),
    .scopeFieldCount=0,
    .v9ScopeLen=0,
    .netflow_device_ip = TEST_SAVE_AND_LOAD_TEMPLATE_EXAMPLE_IP,
    .observation_domain_id = 0,
    .isOptionTemplate = 0,
  },
  .fields = (V9V10TemplateField *) &templateFields,
  .next = NULL
};

static const V9V10TemplateField template2Fields[] =
{
  {.fieldId=8,.fieldLen=4,.isPenField=0,.v9_template=NULL},
  {.fieldId=12,.fieldLen=4,.isPenField=0,.v9_template=NULL},
  {.fieldId=60,.fieldLen=1,.isPenField=0,.v9_template=NULL},
  {.fieldId=4,.fieldLen=1,.isPenField=0,.v9_template=NULL},
  {.fieldId=56,.fieldLen=6,.isPenField=0,.v9_template=NULL},
  {.fieldId=80,.fieldLen=6,.isPenField=0,.v9_template=NULL},
  {.fieldId=136,.fieldLen=1,.isPenField=0,.v9_template=NULL},
  {.fieldId=239,.fieldLen=1,.isPenField=0,.v9_template=NULL},
  {.fieldId=81,.fieldLen=6,.isPenField=0,.v9_template=NULL},
  {.fieldId=57,.fieldLen=6,.isPenField=0,.v9_template=NULL},
  {.fieldId=61,.fieldLen=1,.isPenField=0,.v9_template=NULL},
  {.fieldId=48,.fieldLen=1,.isPenField=0,.v9_template=NULL},
  {.fieldId=95,.fieldLen=4,.isPenField=0,.v9_template=NULL},
  {.fieldId=12235,.fieldLen=65535,.isPenField=1,.v9_template=NULL},
  {.fieldId=12235,.fieldLen=65535,.isPenField=1,.v9_template=NULL},
  {.fieldId=12235,.fieldLen=65535,.isPenField=1,.v9_template=NULL},
  {.fieldId=12235,.fieldLen=65535,.isPenField=1,.v9_template=NULL},
  {.fieldId=1,.fieldLen=8,.isPenField=0,.v9_template=NULL},
  {.fieldId=2,.fieldLen=4,.isPenField=0,.v9_template=NULL},
  {.fieldId=22,.fieldLen=4,.isPenField=0,.v9_template=NULL},
  {.fieldId=21,.fieldLen=4,.isPenField=0,.v9_template=NULL},
};

static const FlowSetV9Ipfix example_template2 =
{
  .templateInfo = {
    .flowsetLen = 104,
    /* V9TemplateDef */
    .templateId = 265,
    .fieldCount = sizeof(templateFields)/sizeof(templateFields[0]),
    .scopeFieldCount=0,
    .v9ScopeLen=0,
    .netflow_device_ip = TEST_SAVE_AND_LOAD_TEMPLATE_EXAMPLE_IP,
    .observation_domain_id = 0,
    .isOptionTemplate = 0,
  },
  .fields = (V9V10TemplateField *) &templateFields,
  .next = NULL
};

static void  assertTemplateEquals(const FlowSetV9Ipfix *t1,const FlowSetV9Ipfix *t2)
{
  assert(t1->templateInfo.flowsetLen == t2->templateInfo.flowsetLen);
  assert(t1->templateInfo.templateId == t2->templateInfo.templateId);
  assert(t1->templateInfo.fieldCount == t2->templateInfo.fieldCount);
  assert(t1->templateInfo.scopeFieldCount == t2->templateInfo.scopeFieldCount);
  assert(t1->templateInfo.v9ScopeLen == t2->templateInfo.v9ScopeLen);
  assert(t1->templateInfo.netflow_device_ip == t2->templateInfo.netflow_device_ip);
  assert(t1->templateInfo.observation_domain_id == t2->templateInfo.observation_domain_id);
  assert(t1->templateInfo.isOptionTemplate == t2->templateInfo.isOptionTemplate);
  int i;
  for(i=0; i<(t2->templateInfo.fieldCount);++i)
  {
    traceEvent(TRACE_NORMAL,"testing field %d/%d",i,t2->templateInfo.fieldCount);
    assert(t1->fields[i].fieldId == t2->fields[i].fieldId);
    assert(t1->fields[i].isPenField == t2->fields[i].isPenField);
    // assert(find_template(t1->fields[i].fieldId) == t2->fields[i].v9_template);
  }
}

static void testSaveAndLoadTemplate_fullOKtest()
{
  static const char *SAVED_TEMPLATE_FILENAME = "template_temp.dat";

  const int saveTemplateRet = saveTemplateInFile(&example_template,SAVED_TEMPLATE_FILENAME);
  assert(saveTemplateRet == 1);

  FlowSetV9Ipfix *loaded_template = loadTemplate(SAVED_TEMPLATE_FILENAME);
  traceEvent(TRACE_NORMAL,"Comparing template info");

  assertTemplateEquals(loaded_template,&example_template);

  unlink(SAVED_TEMPLATE_FILENAME);
}

static void testSaveTemplateInDatabase()
{
  traceEvent(TRACE_NORMAL,"************************************");
  traceEvent(TRACE_NORMAL,"TESTING SAVING TEMPLATES IN DATABASE");
  traceEvent(TRACE_NORMAL,"************************************");

  struct rb_sensors_db *sensors = allocate_rb_sensors_db();
  add_forced_sensor(sensors,"sensor_test",example_ip);

  FlowSetV9Ipfix example_template1;
  FlowSetV9Ipfix example_template2;

  memcpy(&example_template1,&example_template,sizeof(example_template));
  memcpy(&example_template2,&example_template,sizeof(example_template));

  example_template2.templateInfo.templateId = 600;

  saveTemplate(sensors,&example_template1);

  const FlowSetV9Ipfix *saved_template
    = find_sensor_template(sensors,example_template1.templateInfo.netflow_device_ip,example_template1.templateInfo.templateId);
    assert(saved_template == &example_template1);

  saveTemplate(sensors,&example_template2);
  saved_template = find_sensor_template(sensors,example_template2.templateInfo.netflow_device_ip,example_template2.templateInfo.templateId);
  assert(saved_template != NULL);
}

#endif

static void testSaveAndLoadTemplate()
{
  // testSaveTemplateInDatabase();
  // testSaveAndLoadTemplate_loadFromInvalidFile();
  // testSaveAndLoadTemplate_fullOKtest();
}

int main(void){
	testSaveAndLoadTemplate();
	return 0;
}
