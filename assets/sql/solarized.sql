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
-- Name: solarized; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.solarized (
    id integer NOT NULL,
    colour_name character varying(50) NOT NULL,
    hex_value character(7) NOT NULL,
    rgb_value character varying(15) NOT NULL
);


ALTER TABLE public.solarized OWNER TO postgres;

--
-- Name: solarized_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.solarized_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.solarized_id_seq OWNER TO postgres;

--
-- Name: solarized_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.solarized_id_seq OWNED BY public.solarized.id;


--
-- Name: solarized id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.solarized ALTER COLUMN id SET DEFAULT nextval('public.solarized_id_seq'::regclass);


--
-- Data for Name: solarized; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.solarized (id, colour_name, hex_value, rgb_value) FROM stdin;
1	Base03	#002b36	0,43,54
2	Base02	#073642	7,54,66
3	Base01	#586e75	88,110,117
4	Base00	#657b83	101,123,131
5	Base0	#839496	131,148,150
6	Base1	#93a1a1	147,161,161
7	Base2	#eee8d5	238,232,213
8	Base3	#fdf6e3	253,246,227
9	Yellow	#b58900	181,137,0
10	Orange	#cb4b16	203,75,22
11	Red	#dc322f	220,50,47
12	Magenta	#d33682	211,54,130
13	Violet	#6c71c4	108,113,196
14	Blue	#268bd2	38,139,210
15	Cyan	#2aa198	42,161,152
16	Green	#859900	133,153,0
\.


--
-- Name: solarized_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_cataotelzap.Ctx(rc.Ctx).setval('public.solarized_id_seq', 16, true);


--
-- Name: solarized solarized_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.solarized
    ADD CONSTRAINT solarized_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

