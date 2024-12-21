#!/bin/bash

sudo -u postgres psql -d "colours_db"<<EOF
CREATE TABLE IF NOT EXISTS solarized (
    id SERIAL PRIMARY KEY,
    colour_name VARCHAR(50) NOT NULL,
    hex_value CHAR(7) NOT NULL,
    rgb_value VARCHAR(15) NOT NULL
);

INSERT INTO solarized (colour_name, hex_value, rgb_value) VALUES
('Base03', '#002b36', '0,43,54'),
('Base02', '#073642', '7,54,66'),
('Base01', '#586e75', '88,110,117'),
('Base00', '#657b83', '101,123,131'),
('Base0', '#839496', '131,148,150'),
('Base1', '#93a1a1', '147,161,161'),
('Base2', '#eee8d5', '238,232,213'),
('Base3', '#fdf6e3', '253,246,227'),
('Yellow', '#b58900', '181,137,0'),
('Orange', '#cb4b16', '203,75,22'),
('Red', '#dc322f', '220,50,47'),
('Magenta', '#d33682', '211,54,130'),
('Violet', '#6c71c4', '108,113,196'),
('Blue', '#268bd2', '38,139,210'),
('Cyan', '#2aa198', '42,161,152'),
('Green', '#859900', '133,153,0')
ON CONFLICT (colour_name) DO NOTHING;
EOF