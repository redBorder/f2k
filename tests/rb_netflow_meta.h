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

#ifdef __GNUC__
// For some reason, GCC <= 4.7 does not provide these macros
#if !__GNUC_PREREQ(4,8)
#define __BYTE_ORDER__ __BYTE_ORDER
#define __ORDER_LITTLE_ENDIAN__ __LITTLE_ENDIAN
#define __ORDER_BIG_ENDIAN__ __BIG_ENDIAN
#define __builtin_bswap16(a) (((a)&0xff)<<8u)|((a)>>8u)
#endif // GCC < 4.8
#endif // __GNUC__

#if __BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__
#define constexpr_be16toh(x) __builtin_bswap16(x)
#define constexpr_be32toh(x) __builtin_bswap32(x)
#else
#define constexpr_be16toh(x) (x)
#define constexpr_be32toh(x) (x)
#endif

#define ARGS(...) __VA_ARGS__

#define NF5_IP(a, b, c, d) constexpr_be32toh((((a)<<24)|((b)<<16)|((c)<<8)|(d)))

// Convert an uint16_t to BIG ENDIAN uint8_t[2] array initializer
#define UINT16_TO_UINT8_ARR(x) ((x)>>8), ((x)&0xff)

#define UINT32_TO_UINT8_ARR(x) \
	UINT16_TO_UINT8_ARR((x)>>16), UINT16_TO_UINT8_ARR((x)&0xffff)

#define UINT64_TO_UINT8_ARR(x) \
	UINT32_TO_UINT8_ARR((x##l)>>32), UINT32_TO_UINT8_ARR((x##l)&0xffffffff)

#define TEMPLATE_ENTITY(entity, len) \
	UINT16_TO_UINT8_ARR(entity), UINT16_TO_UINT8_ARR(len)

#define TEMPLATE_PRIVATE_ENTITY(field_type, len, pen) \
	UINT16_TO_UINT8_ARR(field_type | 0x8000), \
	UINT16_TO_UINT8_ARR(len), UINT32_TO_UINT8_ARR(pen)

#define FLOW_APPLICATION_ID(type, id) UINT32_TO_UINT8_ARR(type<<24 | id)

/* ********************** TEMPLATE & FLOW COMMON STUFF ********************** */
#define BYTE_ARRAY_SIZE(...) sizeof((uint8_t[]){ __VA_ARGS__ })
#define NOTHING(...)

/* ***************************** TEMPLATE STUFF ***************************** */
#define TEMPLATE_BYTES_0(entity, length, pen) \
				TEMPLATE_ENTITY(entity, length)
#define TEMPLATE_BYTES_9(entity, length, pen) \
				TEMPLATE_PRIVATE_ENTITY(entity, length, pen) \

#define TEMPLATE_BYTES(entity, length, pen, ...) \
				TEMPLATE_BYTES_##pen(entity, length, pen),

#define TEMPLATE_ENTITY_SIZE(entity, length, pen, ...) \
	+BYTE_ARRAY_SIZE(TEMPLATE_BYTES(entity, length, pen, __VA_ARGS__))
#define TEMPLATE_BYTES_LENGTH(ENTITIES) ENTITIES(TEMPLATE_ENTITY_SIZE, NOTHING)

#define R_1(...) +1
#define TEMPLATE_ENTITIES_COUNT(ENTITIES) ENTITIES(R_1, NOTHING)

#define NF9_TEMPLATE_ENTITY(entity, length, ...) \
	{ .templateId = constexpr_be16toh(entity), \
	  .flowsetLen = constexpr_be16toh(length)},

#define NF9_TEMPLATE_ENTITIES(ENTITIES) ENTITIES(NF9_TEMPLATE_ENTITY, NOTHING)

#define NF9_TEMPLATE_SET(flowset_var, template_header_var, template_var, \
		TEMPLATE_ID, ENTITIES) \
	.flowset_var = { \
		.templateFlowset = 0, \
		.flowsetLen = constexpr_be16toh(sizeof(V9TemplateHeader) + \
				sizeof(V9TemplateDef) + \
				TEMPLATE_BYTES_LENGTH(ENTITIES)), \
	}, .template_header_var = { \
		.templateId = constexpr_be16toh(TEMPLATE_ID), \
		.fieldCount = \
			constexpr_be16toh(TEMPLATE_ENTITIES_COUNT(ENTITIES)), \
	}, .template_var = { NF9_TEMPLATE_ENTITIES(ENTITIES) }

#define NF9_TEMPLATE(var, FLOW_HEADER, TEMPLATE_ID, ENTITIES) \
struct { \
	V9FlowHeader flow_header; \
	V9TemplateHeader flow_set_header; \
	V9TemplateDef template_header; \
	V9FlowSet template_set[TEMPLATE_ENTITIES_COUNT(ENTITIES)]; \
} __attribute__((packed)) var = { \
	.flow_header = { \
		.version = constexpr_be16toh(9), \
		.count = constexpr_be16toh(1), \
		FLOW_HEADER \
	}, \
	NF9_TEMPLATE_SET(flow_set_header, template_header, template_set, \
		TEMPLATE_ID, ENTITIES) \
};

#define COUNT_4(...) +4
#define NF9_OPTION_TEMPLATE_ENTITY(type, length, ...) { \
	.templateId = constexpr_be16toh(type), \
	.flowsetLen = constexpr_be16toh(length)},

#define PADDING_SUM(...) +BYTE_ARRAY_SIZE(__VA_ARGS__)
#define NF9_OPTION_TEMPLATE_SCOPE_LEN(ENTITIES) \
	ENTITIES(COUNT_4, NOTHING, NOTHING, NOTHING, NOTHING, NOTHING)
#define NF9_OPTION_TEMPLATE_OPTION_LEN(ENTITIES) \
	ENTITIES(NOTHING, COUNT_4, NOTHING, NOTHING, NOTHING, NOTHING)
#define NF9_OPTION_TEMPLATE_PADDING_LEN(ENTITIES) \
	ENTITIES(NOTHING, NOTHING, PADDING_SUM, NOTHING, NOTHING, NOTHING)
#define OPTION_TEMPLATE_LEN(ENTITIES) \
	ENTITIES(COUNT_4, COUNT_4, PADDING_SUM, NOTHING, NOTHING, NOTHING)
#define OPTION_TEMPLATE_ENTITIES(ENTITIES) \
	ENTITIES(NF9_OPTION_TEMPLATE_ENTITY, NF9_OPTION_TEMPLATE_ENTITY, \
		NOTHING, NOTHING, NOTHING, NOTHING)
#define OPTION_TEMPLATE_SCOPE_ENTITIES_COUNT(ENTITIES) \
	ENTITIES(R_1, NOTHING, NOTHING, NOTHING, NOTHING, NOTHING)
#define OPTION_TEMPLATE_ENTITIES_COUNT(ENTITIES) \
	ENTITIES(R_1, R_1, NOTHING, NOTHING, NOTHING, NOTHING)
#define NF9_OPTION_TEMPLATE_PADDING(ENTITIES) \
	ENTITIES(R_1, R_1, NOTHING, NOTHING, NOTHING, NOTHING)

#define NF9_OPTION_TEMPLATE(var, FLOW_HEADER, TEMPLATE_ID, ENTITIES) \
struct { \
	V9FlowHeader flow_header; \
	V9TemplateHeader flow_set_header; \
	V9OptionTemplate template_header; \
	V9FlowSet template_set[OPTION_TEMPLATE_ENTITIES_COUNT(ENTITIES)]; \
	uint8_t padding[NF9_OPTION_TEMPLATE_PADDING_LEN(ENTITIES)]; \
} __attribute__((packed)) var = { \
	.flow_header = { \
		.version = constexpr_be16toh(9), \
		.count = constexpr_be16toh(1), \
		FLOW_HEADER \
	}, .flow_set_header = { \
		.templateFlowset = constexpr_be16toh(1), \
		.flowsetLen = \
			constexpr_be16toh(10 \
				OPTION_TEMPLATE_LEN(ENTITIES)), \
	}, .template_header = { \
		.template_id = constexpr_be16toh(TEMPLATE_ID), \
		.option_scope_len = constexpr_be16toh( \
			NF9_OPTION_TEMPLATE_SCOPE_LEN(ENTITIES)), \
		.option_len = constexpr_be16toh( \
			NF9_OPTION_TEMPLATE_OPTION_LEN(ENTITIES)) , \
	}, .template_set = { OPTION_TEMPLATE_ENTITIES(ENTITIES) } \
}

#define IPFIX_TEMPLATE_SET(flowset_header_var, template_header_var, \
		template_buffer_var, TEMPLATE_ID, ENTITIES) \
	}, .flowset_header_var = { \
		.set_id = constexpr_be16toh(2), \
		.set_len = constexpr_be16toh( \
			TEMPLATE_BYTES_LENGTH(ENTITIES) \
			+ sizeof(V9TemplateDef) + sizeof(IPFIXSet)), \
	}, .template_header_var = { \
		.templateId = constexpr_be16toh(TEMPLATE_ID), \
		.fieldCount = constexpr_be16toh( \
			TEMPLATE_ENTITIES_COUNT(ENTITIES)), \
	}, .template_buffer_var = { ENTITIES(TEMPLATE_BYTES, NOTHING) }

#define IPFIX_TEMPLATE(var, FLOW_HEADER, TEMPLATE_ID, ENTITIES) \
struct { \
	IPFIXFlowHeader flowHeader; \
	IPFIXSet flowSetHeader; \
	V9TemplateDef templateHeader; /* It's the same */ \
	uint8_t templateBuffer[TEMPLATE_BYTES_LENGTH(ENTITIES)]; \
} __attribute__((packed)) var = { \
	.flowHeader = { \
		.version = constexpr_be16toh(10), \
		.len = constexpr_be16toh(TEMPLATE_BYTES_LENGTH(ENTITIES) \
			+ sizeof(V9TemplateDef) + sizeof(IPFIXSet) \
			+ sizeof(IPFIXFlowHeader)), \
		FLOW_HEADER \
	IPFIX_TEMPLATE_SET(flowSetHeader, templateHeader, templateBuffer, \
		TEMPLATE_ID, ENTITIES) \
}

#define IPFIX_OPTION_TEMPLATE(var, FLOW_HEADER, TEMPLATE_ID, ENTITIES) \
struct { \
	IPFIXFlowHeader flowHeader; \
	IPFIXSet flowSetHeader; \
	IPFIXOptionsTemplate templateHeader; /* It's the same */ \
	V9FlowSet template_set[OPTION_TEMPLATE_ENTITIES_COUNT(ENTITIES)]; \
} __attribute__((packed)) var = { \
	.flowHeader = { \
		.version = constexpr_be16toh(10), \
		.len = constexpr_be16toh(OPTION_TEMPLATE_LEN(ENTITIES) \
			+ sizeof(IPFIXOptionsTemplate) + sizeof(IPFIXSet) \
			+ sizeof(IPFIXFlowHeader)), \
		FLOW_HEADER \
	}, .flowSetHeader = { \
		.set_id = constexpr_be16toh(3), \
		.set_len = constexpr_be16toh(OPTION_TEMPLATE_LEN(ENTITIES) \
			+ sizeof(IPFIXOptionsTemplate) + sizeof(IPFIXSet)), \
	}, .templateHeader = { \
		.template_id = constexpr_be16toh(TEMPLATE_ID), \
		.total_field_count = constexpr_be16toh( \
			OPTION_TEMPLATE_ENTITIES_COUNT(ENTITIES)), \
		.scope_field_count = constexpr_be16toh( \
			OPTION_TEMPLATE_SCOPE_ENTITIES_COUNT(ENTITIES)) \
	}, .template_set = { OPTION_TEMPLATE_ENTITIES(ENTITIES) }}

/* ******************************* FLOW STUFF ******************************* */
#define FLOW_BYTES(entity, length, pen, ...) __VA_ARGS__,

#define FLOW_ENTITY_SIZE(entity, length, pen, ...) \
	+BYTE_ARRAY_SIZE(FLOW_BYTES(entity, length, pen, __VA_ARGS__))
#define FLOW_BYTES_LENGTH(ENTITIES) ENTITIES(FLOW_ENTITY_SIZE, FLOW_ENTITY_SIZE)

#define NF9_FLOW0(var, FLOW_HEADER, TEMPLATE_ID, BUFFER_LEN, ...) \
struct { \
	V9FlowHeader flow_header; \
	V9TemplateHeader flow_set_header; \
	uint8_t buffer[BUFFER_LEN]; \
} var = { \
	.flow_header = { \
		.version = constexpr_be16toh(9), \
		.count = constexpr_be16toh(1), \
		FLOW_HEADER \
	}, .flow_set_header = { \
		.templateFlowset = constexpr_be16toh(TEMPLATE_ID), \
		.flowsetLen = \
			constexpr_be16toh(BUFFER_LEN + \
				sizeof(V9TemplateHeader)), \
	}, .buffer = { __VA_ARGS__ } \
}

#define NF9_FLOW(var, FLOW_HEADER, TEMPLATE_ID, ENTITIES) \
	NF9_FLOW0(var, ARGS(FLOW_HEADER), TEMPLATE_ID, \
		FLOW_BYTES_LENGTH(ENTITIES), ENTITIES(FLOW_BYTES, FLOW_BYTES))

#define OPTION_FLOW_ENTITY_BYTES_LENGTH(type, len, ...) \
	+BYTE_ARRAY_SIZE(__VA_ARGS__)
#define OPTION_FLOW_BYTES_LENGTH(ENTITIES) \
	ENTITIES(OPTION_FLOW_ENTITY_BYTES_LENGTH, \
		OPTION_FLOW_ENTITY_BYTES_LENGTH, \
		NOTHING, \
		OPTION_FLOW_ENTITY_BYTES_LENGTH, \
		OPTION_FLOW_ENTITY_BYTES_LENGTH, \
		PADDING_SUM)
#define OPTION_FLOW_ENTITY_BYTES(type, len, ...) __VA_ARGS__,
#define OPTION_FLOW_BYTES(ENTITIES) \
	ENTITIES(OPTION_FLOW_ENTITY_BYTES, \
		OPTION_FLOW_ENTITY_BYTES, \
		NOTHING, \
		OPTION_FLOW_ENTITY_BYTES, \
		OPTION_FLOW_ENTITY_BYTES, \
		NOTHING)
#define NF9_OPTION_FLOW(var, FLOW_HEADER, TEMPLATE_ID, ENTITIES) \
	NF9_FLOW0(var, ARGS(FLOW_HEADER), TEMPLATE_ID, \
		OPTION_FLOW_BYTES_LENGTH(ENTITIES), \
		OPTION_FLOW_BYTES(ENTITIES))

#define IPFIX_FLOW0(var, FLOW_HEADER, TEMPLATE_ID, ENTITIES_LEN, ...) \
struct { \
	IPFIXFlowHeader flowHeader; \
	IPFIXSet flowSetHeader; \
	uint8_t buffer1[ENTITIES_LEN]; \
} __attribute__((packed)) var = { \
	.flowHeader = { \
		.version = constexpr_be16toh(10), \
		.len = constexpr_be16toh(ENTITIES_LEN \
				+ sizeof(IPFIXSet) + sizeof(IPFIXFlowHeader)), \
		FLOW_HEADER \
	}, .flowSetHeader = { \
		.set_id = constexpr_be16toh(TEMPLATE_ID), \
		.set_len = constexpr_be16toh(ENTITIES_LEN + sizeof(IPFIXSet)), \
	}, .buffer1 = {	__VA_ARGS__ }, \
};

#define IPFIX_FLOW(var, FLOW_HEADER, TEMPLATE_ID, ENTITIES) \
	IPFIX_FLOW0(var, ARGS(FLOW_HEADER), TEMPLATE_ID, \
		FLOW_BYTES_LENGTH(ENTITIES), ENTITIES(FLOW_BYTES, FLOW_BYTES))

#define IPFIX_OPTION_FLOW(var, FLOW_HEADER, TEMPLATE_ID, ENTITIES) \
	IPFIX_FLOW0(var, ARGS(FLOW_HEADER), TEMPLATE_ID, \
		OPTION_FLOW_BYTES_LENGTH(ENTITIES), \
		OPTION_FLOW_BYTES(ENTITIES))

/* ************************************************************************** */

// Netflow9 template + flow in the same message
#define NF9_TEMPLATE_FLOW(var, FLOW_HEADER, TEMPLATE_ID, ENTITIES) \
struct { \
	V9FlowHeader flow_header; \
	V9TemplateHeader t_flow_set_header; \
	V9TemplateDef template_header; \
	V9FlowSet template_set[TEMPLATE_ENTITIES_COUNT(ENTITIES)]; \
	V9TemplateHeader f_flow_set_header; \
	uint8_t buffer[FLOW_BYTES_LENGTH(ENTITIES)]; \
} __attribute__((packed)) var = { \
	.flow_header = { \
		.version = constexpr_be16toh(9), \
		.count = constexpr_be16toh(2), \
		FLOW_HEADER \
	}, \
	NF9_TEMPLATE_SET(t_flow_set_header, template_header, template_set, \
		TEMPLATE_ID, ENTITIES), \
	.f_flow_set_header = { \
		.templateFlowset = constexpr_be16toh(TEMPLATE_ID), \
		.flowsetLen = \
			constexpr_be16toh(FLOW_BYTES_LENGTH(ENTITIES) + \
				sizeof(V9TemplateHeader)), \
	}, .buffer = { ENTITIES(FLOW_BYTES, FLOW_BYTES) } \
}

// IPFIX template + flow in the same message
#define IPFIX_TEMPLATE_FLOW(var, FLOW_HEADER, TEMPLATE_ID, ENTITIES) \
struct { \
	IPFIXFlowHeader flowHeader; \
	IPFIXSet flowSetHeader; \
	V9TemplateDef templateHeader; /* It's the same */ \
	uint8_t templateBuffer[TEMPLATE_BYTES_LENGTH(ENTITIES)]; \
	IPFIXSet f_flow_set_header; \
	uint8_t buffer[FLOW_BYTES_LENGTH(ENTITIES)]; \
} __attribute__((packed)) var = { \
	.flowHeader = { \
		.version = constexpr_be16toh(10), \
		.len = constexpr_be16toh(TEMPLATE_BYTES_LENGTH(ENTITIES) \
			+ sizeof(V9TemplateDef) + 2*sizeof(IPFIXSet) \
			+ sizeof(IPFIXFlowHeader) + \
			FLOW_BYTES_LENGTH(ENTITIES)), \
		FLOW_HEADER \
	IPFIX_TEMPLATE_SET(flowSetHeader, templateHeader, templateBuffer, \
		TEMPLATE_ID, ENTITIES), \
	.f_flow_set_header = { \
		.set_id = constexpr_be16toh(TEMPLATE_ID), \
		.set_len = \
			constexpr_be16toh(FLOW_BYTES_LENGTH(ENTITIES) + \
				sizeof(V9TemplateHeader)), \
	}, .buffer = { ENTITIES(FLOW_BYTES, FLOW_BYTES) } \
}
