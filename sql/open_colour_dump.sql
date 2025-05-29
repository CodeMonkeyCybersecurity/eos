--
-- PostgreSQL database dump
--

-- Dumped from database version 16.6 (Ubuntu 16.6-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.6 (Ubuntu 16.6-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_cataotelzap.Ctx(rc.Ctx).set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: open_colour; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.open_colour (
    id integer NOT NULL,
    colour_name character varying(50) NOT NULL,
    hex_value character(7) NOT NULL,
    rgb_value character varying(15) NOT NULL
);


ALTER TABLE public.open_colour OWNER TO postgres;

--
-- Name: open_colour_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.open_colour_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.open_colour_id_seq OWNER TO postgres;

--
-- Name: open_colour_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.open_colour_id_seq OWNED BY public.open_colour.id;


--
-- Name: open_colour id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.open_colour ALTER COLUMN id SET DEFAULT nextval('public.open_colour_id_seq'::regclass);


--
-- Data for Name: open_colour; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.open_colour (id, colour_name, hex_value, rgb_value) FROM stdin;
1	White	#ffffff	255,255,255
2	Black	#000000	0,0,0
3	Gray 0	#f8f9fa	248,249,250
4	Gray 1	#f1f3f5	241,243,245
5	Gray 2	#e9ecef	233,236,239
6	Gray 3	#dee2e6	222,226,230
7	Gray 4	#ced4da	206,212,218
8	Gray 5	#adb5bd	173,181,189
9	Gray 6	#868e96	134,142,150
10	Gray 7	#495057	73,80,87
11	Gray 8	#343a40	52,58,64
12	Gray 9	#212529	33,37,41
13	Red 0	#fff5f5	255,245,245
14	Red 1	#ffe3e3	255,227,227
15	Red 2	#ffc9c9	255,201,201
16	Red 3	#ffa8a8	255,168,168
17	Red 4	#ff8787	255,135,135
18	Red 5	#ff6b6b	255,107,107
19	Red 6	#fa5252	250,82,82
20	Red 7	#f03e3e	240,62,62
21	Red 8	#e03131	224,49,49
22	Red 9	#c92a2a	201,42,42
23	Pink 0	#fff0f6	255,240,246
24	Pink 1	#ffdeeb	255,222,235
25	Pink 2	#fcc2d7	252,194,215
26	Pink 3	#faa2c1	250,162,193
27	Pink 4	#f783ac	247,131,172
28	Pink 5	#f06595	240,101,149
29	Pink 6	#e64980	230,73,128
30	Pink 7	#d6336c	214,51,108
31	Pink 8	#c2255c	194,37,92
32	Pink 9	#a61e4d	166,30,77
33	Grape 0	#f8f0fc	248,240,252
34	Grape 1	#f3d9fa	243,217,250
35	Grape 2	#eebefa	238,190,250
36	Grape 3	#e599f7	229,153,247
37	Grape 4	#da77f2	218,119,242
38	Grape 5	#cc5de8	204,93,232
39	Grape 6	#be4bdb	190,75,219
40	Grape 7	#ae3ec9	174,62,201
41	Grape 8	#9c36b5	156,54,181
42	Grape 9	#862e9c	134,46,156
43	Violet 0	#f3f0ff	243,240,255
44	Violet 1	#e5dbff	229,219,255
45	Violet 2	#d0bfff	208,191,255
46	Violet 3	#b197fc	177,151,252
47	Violet 4	#9775fa	151,117,250
48	Violet 5	#845ef7	132,94,247
49	Violet 6	#7950f2	121,80,242
50	Violet 7	#7048e8	112,72,232
51	Violet 8	#6741d9	103,65,217
52	Violet 9	#5f3dc4	95,61,196
53	Indigo 0	#edf2ff	237,242,255
54	Indigo 1	#dbe4ff	219,228,255
55	Indigo 2	#bac8ff	186,200,255
56	Indigo 3	#91a7ff	145,167,255
57	Indigo 4	#748ffc	116,143,252
58	Indigo 5	#5c7cfa	92,124,250
59	Indigo 6	#4c6ef5	76,110,245
60	Indigo 7	#4263eb	66,99,235
61	Indigo 8	#3b5bdb	59,91,219
62	Indigo 9	#364fc7	54,79,199
63	Blue 0	#e7f5ff	231,245,255
64	Blue 1	#d0ebff	208,235,255
65	Blue 2	#a5d8ff	165,216,255
66	Blue 3	#74c0fc	116,192,252
67	Blue 4	#4dabf7	77,171,247
68	Blue 5	#339af0	51,154,240
69	Blue 6	#228be6	34,139,230
70	Blue 7	#1c7ed6	28,126,214
71	Blue 8	#1971c2	25,113,194
72	Blue 9	#1864ab	24,100,171
73	Cyan 0	#e3fafc	227,250,252
74	Cyan 1	#c5f6fa	197,246,250
75	Cyan 2	#99e9f2	153,233,242
76	Cyan 3	#66d9e8	102,217,232
77	Cyan 4	#3bc9db	59,201,219
78	Cyan 5	#22b8cf	34,184,207
79	Cyan 6	#15aabf	21,170,191
80	Cyan 7	#1098ad	16,152,173
81	Cyan 8	#0c8599	12,133,153
82	Cyan 9	#0b7285	11,114,133
83	Teal 0	#e6fcf5	230,252,245
84	Teal 1	#c3fae8	195,250,232
85	Teal 2	#96f2d7	150,242,215
86	Teal 3	#63e6be	99,230,190
87	Teal 4	#38d9a9	56,217,169
88	Teal 5	#20c997	32,201,151
89	Teal 6	#12b886	18,184,134
90	Teal 7	#0ca678	12,166,120
91	Teal 8	#099268	9,146,104
92	Teal 9	#087f5b	8,127,91
93	Green 0	#ebfbee	235,251,238
94	Green 1	#d3f9d8	211,249,216
95	Green 2	#b2f2bb	178,242,187
96	Green 3	#8ce99a	140,233,154
97	Green 4	#69db7c	105,219,124
98	Green 5	#51cf66	81,207,102
99	Green 6	#40c057	64,192,87
100	Green 7	#37b24d	55,178,77
101	Green 8	#2f9e44	47,158,68
102	Green 9	#2b8a3e	43,138,62
103	White	#ffffff	255,255,255
104	Black	#000000	0,0,0
105	Gray 0	#f8f9fa	248,249,250
106	Gray 1	#f1f3f5	241,243,245
107	Gray 2	#e9ecef	233,236,239
108	Gray 3	#dee2e6	222,226,230
109	Gray 4	#ced4da	206,212,218
110	Gray 5	#adb5bd	173,181,189
111	Gray 6	#868e96	134,142,150
112	Gray 7	#495057	73,80,87
113	Gray 8	#343a40	52,58,64
114	Gray 9	#212529	33,37,41
115	Red 0	#fff5f5	255,245,245
116	Red 1	#ffe3e3	255,227,227
117	Red 2	#ffc9c9	255,201,201
118	Red 3	#ffa8a8	255,168,168
119	Red 4	#ff8787	255,135,135
120	Red 5	#ff6b6b	255,107,107
121	Red 6	#fa5252	250,82,82
122	Red 7	#f03e3e	240,62,62
123	Red 8	#e03131	224,49,49
124	Red 9	#c92a2a	201,42,42
125	Pink 0	#fff0f6	255,240,246
126	Pink 1	#ffdeeb	255,222,235
127	Pink 2	#fcc2d7	252,194,215
128	Pink 3	#faa2c1	250,162,193
129	Pink 4	#f783ac	247,131,172
130	Pink 5	#f06595	240,101,149
131	Pink 6	#e64980	230,73,128
132	Pink 7	#d6336c	214,51,108
133	Pink 8	#c2255c	194,37,92
134	Pink 9	#a61e4d	166,30,77
135	Grape 0	#f8f0fc	248,240,252
136	Grape 1	#f3d9fa	243,217,250
137	Grape 2	#eebefa	238,190,250
138	Grape 3	#e599f7	229,153,247
139	Grape 4	#da77f2	218,119,242
140	Grape 5	#cc5de8	204,93,232
141	Grape 6	#be4bdb	190,75,219
142	Grape 7	#ae3ec9	174,62,201
143	Grape 8	#9c36b5	156,54,181
144	Grape 9	#862e9c	134,46,156
145	Violet 0	#f3f0ff	243,240,255
146	Violet 1	#e5dbff	229,219,255
147	Violet 2	#d0bfff	208,191,255
148	Violet 3	#b197fc	177,151,252
149	Violet 4	#9775fa	151,117,250
150	Violet 5	#845ef7	132,94,247
151	Violet 6	#7950f2	121,80,242
152	Violet 7	#7048e8	112,72,232
153	Violet 8	#6741d9	103,65,217
154	Violet 9	#5f3dc4	95,61,196
155	Indigo 0	#edf2ff	237,242,255
156	Indigo 1	#dbe4ff	219,228,255
157	Indigo 2	#bac8ff	186,200,255
158	Indigo 3	#91a7ff	145,167,255
159	Indigo 4	#748ffc	116,143,252
160	Indigo 5	#5c7cfa	92,124,250
161	Indigo 6	#4c6ef5	76,110,245
162	Indigo 7	#4263eb	66,99,235
163	Indigo 8	#3b5bdb	59,91,219
164	Indigo 9	#364fc7	54,79,199
165	Blue 0	#e7f5ff	231,245,255
166	Blue 1	#d0ebff	208,235,255
167	Blue 2	#a5d8ff	165,216,255
168	Blue 3	#74c0fc	116,192,252
169	Blue 4	#4dabf7	77,171,247
170	Blue 5	#339af0	51,154,240
171	Blue 6	#228be6	34,139,230
172	Blue 7	#1c7ed6	28,126,214
173	Blue 8	#1971c2	25,113,194
174	Blue 9	#1864ab	24,100,171
175	Cyan 0	#e3fafc	227,250,252
176	Cyan 1	#c5f6fa	197,246,250
177	Cyan 2	#99e9f2	153,233,242
178	Cyan 3	#66d9e8	102,217,232
179	Cyan 4	#3bc9db	59,201,219
180	Cyan 5	#22b8cf	34,184,207
181	Cyan 6	#15aabf	21,170,191
182	Cyan 7	#1098ad	16,152,173
183	Cyan 8	#0c8599	12,133,153
184	Cyan 9	#0b7285	11,114,133
185	Teal 0	#e6fcf5	230,252,245
186	Teal 1	#c3fae8	195,250,232
187	Teal 2	#96f2d7	150,242,215
188	Teal 3	#63e6be	99,230,190
189	Teal 4	#38d9a9	56,217,169
190	Teal 5	#20c997	32,201,151
191	Teal 6	#12b886	18,184,134
192	Teal 7	#0ca678	12,166,120
193	Teal 8	#099268	9,146,104
194	Teal 9	#087f5b	8,127,91
195	Green 0	#ebfbee	235,251,238
196	Green 1	#d3f9d8	211,249,216
197	Green 2	#b2f2bb	178,242,187
198	Green 3	#8ce99a	140,233,154
199	Green 4	#69db7c	105,219,124
200	Green 5	#51cf66	81,207,102
201	Green 6	#40c057	64,192,87
202	Green 7	#37b24d	55,178,77
203	Green 8	#2f9e44	47,158,68
204	Green 9	#2b8a3e	43,138,62
205	White	#ffffff	255,255,255
206	Black	#000000	0,0,0
207	Gray 0	#f8f9fa	248,249,250
208	Gray 1	#f1f3f5	241,243,245
209	Gray 2	#e9ecef	233,236,239
210	Gray 3	#dee2e6	222,226,230
211	Gray 4	#ced4da	206,212,218
212	Gray 5	#adb5bd	173,181,189
213	Gray 6	#868e96	134,142,150
214	Gray 7	#495057	73,80,87
215	Gray 8	#343a40	52,58,64
216	Gray 9	#212529	33,37,41
217	Red 0	#fff5f5	255,245,245
218	Red 1	#ffe3e3	255,227,227
219	Red 2	#ffc9c9	255,201,201
220	Red 3	#ffa8a8	255,168,168
221	Red 4	#ff8787	255,135,135
222	Red 5	#ff6b6b	255,107,107
223	Red 6	#fa5252	250,82,82
224	Red 7	#f03e3e	240,62,62
225	Red 8	#e03131	224,49,49
226	Red 9	#c92a2a	201,42,42
227	Pink 0	#fff0f6	255,240,246
228	Pink 1	#ffdeeb	255,222,235
229	Pink 2	#fcc2d7	252,194,215
230	Pink 3	#faa2c1	250,162,193
231	Pink 4	#f783ac	247,131,172
232	Pink 5	#f06595	240,101,149
233	Pink 6	#e64980	230,73,128
234	Pink 7	#d6336c	214,51,108
235	Pink 8	#c2255c	194,37,92
236	Pink 9	#a61e4d	166,30,77
237	Grape 0	#f8f0fc	248,240,252
238	Grape 1	#f3d9fa	243,217,250
239	Grape 2	#eebefa	238,190,250
240	Grape 3	#e599f7	229,153,247
241	Grape 4	#da77f2	218,119,242
242	Grape 5	#cc5de8	204,93,232
243	Grape 6	#be4bdb	190,75,219
244	Grape 7	#ae3ec9	174,62,201
245	Grape 8	#9c36b5	156,54,181
246	Grape 9	#862e9c	134,46,156
247	Violet 0	#f3f0ff	243,240,255
248	Violet 1	#e5dbff	229,219,255
249	Violet 2	#d0bfff	208,191,255
250	Violet 3	#b197fc	177,151,252
251	Violet 4	#9775fa	151,117,250
252	Violet 5	#845ef7	132,94,247
253	Violet 6	#7950f2	121,80,242
254	Violet 7	#7048e8	112,72,232
255	Violet 8	#6741d9	103,65,217
256	Violet 9	#5f3dc4	95,61,196
257	Indigo 0	#edf2ff	237,242,255
258	Indigo 1	#dbe4ff	219,228,255
259	Indigo 2	#bac8ff	186,200,255
260	Indigo 3	#91a7ff	145,167,255
261	Indigo 4	#748ffc	116,143,252
262	Indigo 5	#5c7cfa	92,124,250
263	Indigo 6	#4c6ef5	76,110,245
264	Indigo 7	#4263eb	66,99,235
265	Indigo 8	#3b5bdb	59,91,219
266	Indigo 9	#364fc7	54,79,199
267	Blue 0	#e7f5ff	231,245,255
268	Blue 1	#d0ebff	208,235,255
269	Blue 2	#a5d8ff	165,216,255
270	Blue 3	#74c0fc	116,192,252
271	Blue 4	#4dabf7	77,171,247
272	Blue 5	#339af0	51,154,240
273	Blue 6	#228be6	34,139,230
274	Blue 7	#1c7ed6	28,126,214
275	Blue 8	#1971c2	25,113,194
276	Blue 9	#1864ab	24,100,171
277	Cyan 0	#e3fafc	227,250,252
278	Cyan 1	#c5f6fa	197,246,250
279	Cyan 2	#99e9f2	153,233,242
280	Cyan 3	#66d9e8	102,217,232
281	Cyan 4	#3bc9db	59,201,219
282	Cyan 5	#22b8cf	34,184,207
283	Cyan 6	#15aabf	21,170,191
284	Cyan 7	#1098ad	16,152,173
285	Cyan 8	#0c8599	12,133,153
286	Cyan 9	#0b7285	11,114,133
287	Teal 0	#e6fcf5	230,252,245
288	Teal 1	#c3fae8	195,250,232
289	Teal 2	#96f2d7	150,242,215
290	Teal 3	#63e6be	99,230,190
291	Teal 4	#38d9a9	56,217,169
292	Teal 5	#20c997	32,201,151
293	Teal 6	#12b886	18,184,134
294	Teal 7	#0ca678	12,166,120
295	Teal 8	#099268	9,146,104
296	Teal 9	#087f5b	8,127,91
297	Green 0	#ebfbee	235,251,238
298	Green 1	#d3f9d8	211,249,216
299	Green 2	#b2f2bb	178,242,187
300	Green 3	#8ce99a	140,233,154
301	Green 4	#69db7c	105,219,124
302	Green 5	#51cf66	81,207,102
303	Green 6	#40c057	64,192,87
304	Green 7	#37b24d	55,178,77
305	Green 8	#2f9e44	47,158,68
306	Green 9	#2b8a3e	43,138,62
\.


--
-- Name: open_colour_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_cataotelzap.Ctx(rc.Ctx).setval('public.open_colour_id_seq', 306, true);


--
-- Name: open_colour open_colour_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.open_colour
    ADD CONSTRAINT open_colour_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

