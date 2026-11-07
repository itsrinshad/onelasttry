-- SYMBIOTES AUTH UPGRADE  (run ONCE, after SYMBIOTES_SUPABASE_SETUP.sql)
-- Supabase Dashboard > SQL Editor > paste everything > Run

-- 1) New signups keep the exact username + game info, and wait as 'pending'
create or replace function handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
declare u text := left(lower(regexp_replace(coalesce(new.raw_user_meta_data->>'username',split_part(new.email,'@',1)),'[^a-z0-9_]','','g')),24);
begin
 if length(u)<3 then u := u||'user'; end if;
 if exists(select 1 from profiles where username=u) then u := left(u,19)||substr(md5(new.id::text),1,4); end if;
 insert into profiles(id,username,display_name,ff_ign,ff_uid,status)
 values(new.id,u,coalesce(new.raw_user_meta_data->>'username',u),new.raw_user_meta_data->>'ff_ign',new.raw_user_meta_data->>'ff_uid','pending');
 insert into glory_totals(member_id) values(new.id); return new; end $$;

-- 2) Is a username free? (callable before login, from the Sign Up page)
create or replace function username_available(p text) returns boolean language sql stable security definer set search_path=public as $$
 select not exists(select 1 from profiles where username=lower(trim(p))) $$;
grant execute on function username_available(text) to anon, authenticated;

-- 3) Admin: approve a new member
create or replace function admin_approve_user(p_user uuid) returns void language plpgsql security definer set search_path=public as $$
begin
 if not is_admin() then raise exception 'forbidden'; end if;
 update profiles set status='active' where id=p_user;
 perform audit('user_approved',p_user::text,null); end $$;

-- 4) Admin: change a member's password (when they forget it)
create or replace function admin_set_password(p_user uuid,p_password text) returns void language plpgsql security definer set search_path=public,extensions,auth as $$
begin
 if not is_admin() then raise exception 'forbidden'; end if;
 if length(coalesce(p_password,''))<6 then raise exception 'Password must be at least 6 characters'; end if;
 if (select role from profiles where id=p_user) in ('admin','super_admin') and my_role()<>'super_admin' then raise exception 'only super admin can change an admin password'; end if;
 update auth.users set encrypted_password=crypt(p_password,gen_salt('bf')),updated_at=now() where id=p_user;
 delete from auth.sessions where user_id=p_user;
 perform audit('password_changed',p_user::text,null); end $$;

-- 5) Admin: remove (delete) an account completely
create or replace function admin_delete_user(p_user uuid) returns void language plpgsql security definer set search_path=public,auth as $$
declare r record;
begin
 if not is_admin() then raise exception 'forbidden'; end if;
 if p_user=auth.uid() then raise exception 'You cannot remove yourself'; end if;
 if (select role from profiles where id=p_user) in ('admin','super_admin') and my_role()<>'super_admin' then raise exception 'only super admin can remove an admin'; end if;
 for r in select k.conrelid::regclass as t, a.attname as c, a.attnotnull as nn
   from pg_constraint k join pg_attribute a on a.attrelid=k.conrelid and a.attnum=k.conkey[1]
   where k.contype='f' and k.confrelid='public.profiles'::regclass and k.confdeltype='a' loop
  if r.nn then execute format('delete from %s where %I=$1',r.t,r.c) using p_user;
  else execute format('update %s set %I=null where %I=$1',r.t,r.c,r.c) using p_user; end if;
 end loop;
 delete from auth.users where id=p_user;
 perform audit('user_removed',p_user::text,null); end $$;

-- 6) MAKE YOURSELF THE FIRST ADMIN
--    First sign up on the website with your username, then put THAT username below and run this line:
-- update profiles set role='super_admin', status='active' where username='YOUR_USERNAME_HERE';
