-- =====================================================================
-- RAIZ ECOBAGS — configuração do Supabase
-- Cole este arquivo inteiro em: SQL Editor > New query > Run
-- ANTES DE RODAR: troque a senha do admin na linha marcada com  <<<<
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- PRODUTOS (qualquer visitante só LÊ; quem cadastra/remove é o admin) ----------
create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  cat text not null check (cat in ('simples','basica','detalhada')),
  price numeric(10,2) not null check (price > 0),
  description text not null default '',
  image_url text not null default '',
  created_at timestamptz not null default now()
);

-- ---------- PEDIDOS (comprador só ENVIA; só o admin consegue LER) ----------
create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  code text not null,
  buyer_name text not null,
  items jsonb not null,
  total numeric(10,2) not null,
  payment text not null check (payment in ('pix','boleto','cartao')),
  status text not null default 'novo',
  created_at timestamptz not null default now()
);

-- ---------- COMPRADORES (nome + senha; senha guardada criptografada, ninguém lê a tabela direto) ----------
create table if not exists public.shop_users (
  name text primary key,
  display_name text not null,
  password_hash text not null,
  created_at timestamptz not null default now()
);

-- ---------- SENHA DO ADMIN (guardada criptografada) ----------
create table if not exists public.admin_config (
  id int primary key default 1,
  pass_hash text not null
);

insert into public.admin_config (id, pass_hash)
values (1, extensions.crypt('senha', extensions.gen_salt('bf')))   -- <<<< TROQUE 'Senha' PELA SUA SENHA ESCOLHIDA
on conflict (id) do update set pass_hash = excluded.pass_hash;

-- ---------- SEGURANÇA (RLS) ----------
alter table public.products     enable row level security;
alter table public.orders       enable row level security;
alter table public.shop_users   enable row level security;
alter table public.admin_config enable row level security;

revoke all on public.products, public.orders, public.shop_users, public.admin_config from anon, authenticated;

grant select on public.products to anon, authenticated;
grant insert on public.orders   to anon, authenticated;

drop policy if exists products_read  on public.products;
drop policy if exists orders_insert  on public.orders;
create policy products_read on public.products for select to anon, authenticated using (true);
create policy orders_insert on public.orders   for insert to anon, authenticated with check (true);

-- ---------- FUNÇÕES ----------
-- Login / cadastro do comprador
create or replace function public.shop_login(p_name text, p_pass text)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  u public.shop_users;
  k text := lower(trim(coalesce(p_name, '')));
begin
  if k = '' or coalesce(p_pass, '') = '' then return 'invalid'; end if;
  select * into u from public.shop_users where name = k;
  if not found then
    insert into public.shop_users (name, display_name, password_hash)
    values (k, trim(p_name), extensions.crypt(p_pass, extensions.gen_salt('bf')));
    return 'created';
  end if;
  if u.password_hash = extensions.crypt(p_pass, u.password_hash) then return 'ok'; end if;
  return 'wrong';
end $$;

-- Confere a senha do admin
create or replace function public.admin_ok(p_pass text)
returns boolean
language sql
security definer
set search_path = public, extensions
as $$
  select exists (
    select 1 from public.admin_config
    where pass_hash = extensions.crypt(coalesce(p_pass, ''), pass_hash)
  );
$$;

-- Admin: cadastrar produto
create or replace function public.admin_add_product(
  p_pass text, p_name text, p_cat text, p_price numeric, p_desc text, p_image_url text)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if not public.admin_ok(p_pass) then raise exception 'senha invalida'; end if;
  insert into public.products (name, cat, price, description, image_url)
  values (trim(p_name), p_cat, p_price, coalesce(p_desc, ''), coalesce(p_image_url, ''));
end $$;

-- Admin: remover produto
create or replace function public.admin_delete_product(p_pass text, p_id uuid)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if not public.admin_ok(p_pass) then raise exception 'senha invalida'; end if;
  delete from public.products where id = p_id;
end $$;

-- Admin: listar pedidos
create or replace function public.admin_list_orders(p_pass text)
returns setof public.orders
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if not public.admin_ok(p_pass) then raise exception 'senha invalida'; end if;
  return query select * from public.orders order by created_at desc;
end $$;

-- Admin: mudar status do pedido
create or replace function public.admin_set_status(p_pass text, p_id uuid, p_status text)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if not public.admin_ok(p_pass) then raise exception 'senha invalida'; end if;
  update public.orders set status = p_status where id = p_id;
end $$;

-- Libera só as funções necessárias para o site
revoke all on function public.shop_login(text, text) from public;
revoke all on function public.admin_ok(text) from public;
revoke all on function public.admin_add_product(text, text, text, numeric, text, text) from public;
revoke all on function public.admin_delete_product(text, uuid) from public;
revoke all on function public.admin_list_orders(text) from public;
revoke all on function public.admin_set_status(text, uuid, text) from public;

grant execute on function public.shop_login(text, text) to anon, authenticated;
grant execute on function public.admin_ok(text) to anon, authenticated;
grant execute on function public.admin_add_product(text, text, text, numeric, text, text) to anon, authenticated;
grant execute on function public.admin_delete_product(text, uuid) to anon, authenticated;
grant execute on function public.admin_list_orders(text) to anon, authenticated;
grant execute on function public.admin_set_status(text, uuid, text) to anon, authenticated;

-- ---------- FOTOS DOS PRODUTOS (Storage) ----------
insert into storage.buckets (id, name, public)
values ('product-images', 'product-images', true)
on conflict (id) do update set public = true;

drop policy if exists "fotos_leitura" on storage.objects;
drop policy if exists "fotos_upload"  on storage.objects;
create policy "fotos_leitura" on storage.objects for select to anon, authenticated
  using (bucket_id = 'product-images');
create policy "fotos_upload"  on storage.objects for insert to anon, authenticated
  with check (bucket_id = 'product-images');
