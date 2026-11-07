-- SYMBIOTES 2.0 setup. Supabase Dashboard > SQL Editor > run whole file once.
-- Also enable Database > Extensions > pg_cron first.
create extension if not exists pgcrypto;
create extension if not exists pg_cron;
create type app_role as enum ('super_admin','admin','moderator','member');
create type group_role as enum ('owner','admin','moderator','member');

create table profiles(
 id uuid primary key references auth.users on delete cascade,
 username text unique not null check (username ~ '^[a-z0-9_]{3,24}$'),
 display_name text, bio text, avatar_url text, cover_url text,
 ff_ign text, ff_uid text, player_level int, ff_rank text,
 role app_role not null default 'member',
 status text not null default 'pending' check (status in ('pending','active','suspended','banned')),
 banned_until timestamptz, last_seen timestamptz, joined_at timestamptz default now());
alter table profiles enable row level security;

create function my_role() returns app_role language sql stable security definer set search_path=public as $$ select role from profiles where id=auth.uid() $$;
create function is_admin() returns boolean language sql stable security definer set search_path=public as $$ select coalesce(my_role() in ('admin','super_admin'),false) $$;
create function is_mod() returns boolean language sql stable security definer set search_path=public as $$ select coalesce(my_role() in ('moderator','admin','super_admin'),false) $$;
create function is_active() returns boolean language sql stable security definer set search_path=public as $$
 select coalesce((select status='active' or (status in('suspended','banned') and banned_until is not null and banned_until<now()) from profiles where id=auth.uid()),false) $$;

-- audit (immutable)
create table audit_logs(id bigint generated always as identity primary key, actor_id uuid, action text not null, target text, details jsonb, created_at timestamptz default now());
alter table audit_logs enable row level security;
create policy audit_read on audit_logs for select using (is_admin());
create function audit(a text,t text,d jsonb) returns void language sql security definer set search_path=public as $$ insert into audit_logs(actor_id,action,target,details) values(auth.uid(),a,t,d) $$;
revoke execute on function audit(text,text,jsonb) from public,anon,authenticated;
create function no_mutate() returns trigger language plpgsql as $$ begin raise exception 'audit logs are immutable'; end $$;
create trigger audit_immutable before update or delete on audit_logs for each row execute function no_mutate();

-- profiles: policies + privilege-escalation guard
create policy p_sel on profiles for select to authenticated using (true);
create policy p_upd on profiles for update to authenticated using (id=auth.uid() or is_admin()) with check (id=auth.uid() or is_admin());
create function guard_profile() returns trigger language plpgsql security definer set search_path=public as $$
begin
 if auth.uid() is not null then
  if (new.role<>old.role or new.status<>old.status or new.banned_until is distinct from old.banned_until) and not is_admin() then raise exception 'forbidden'; end if;
  if new.role<>old.role and my_role()<>'super_admin' then raise exception 'only super admin can change roles'; end if;
 end if; return new; end $$;
create trigger t_guard_profile before update on profiles for each row execute function guard_profile();

-- glory
create table glory_daily(id bigint generated always as identity primary key, member_id uuid not null references profiles on delete cascade, day date not null, gained int not null check(gained>=0), submitted_by uuid references profiles, created_at timestamptz default now(), unique(member_id,day));
create table glory_totals(member_id uuid primary key references profiles on delete cascade, weekly int not null default 0, lifetime int not null default 0);
create table glory_weeks(week_start date not null, member_id uuid not null references profiles on delete cascade, total int not null, rank int, finalized_at timestamptz default now(), primary key(week_start,member_id));
create table glory_corrections(id bigint generated always as identity primary key, member_id uuid, day date, old_value int, new_value int, reason text, corrected_by uuid, created_at timestamptz default now());
create table week_runs(week_start date primary key, processed_at timestamptz default now());
alter table glory_daily enable row level security; alter table glory_totals enable row level security; alter table glory_weeks enable row level security; alter table glory_corrections enable row level security; alter table week_runs enable row level security;
create policy gd_sel on glory_daily for select to authenticated using (member_id=auth.uid() or is_admin());
create policy gt_sel on glory_totals for select to authenticated using (member_id=auth.uid() or is_admin());
create policy gw_sel on glory_weeks for select to authenticated using (true);
create policy gc_sel on glory_corrections for select to authenticated using (is_admin());
-- no insert/update/delete policies: glory changes only through the functions below

create function handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
declare u text := left(lower(regexp_replace(coalesce(new.raw_user_meta_data->>'username',split_part(new.email,'@',1)),'[^a-z0-9_]','','g')),16)||substr(md5(new.id::text),1,4);
begin
 insert into profiles(id,username,display_name) values(new.id,u,coalesce(new.raw_user_meta_data->>'username',u));
 insert into glory_totals(member_id) values(new.id); return new; end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function handle_new_user();

create function submit_daily_glory(entries jsonb) returns int language plpgsql security definer set search_path=public as $$
declare t timestamp := now() at time zone 'Asia/Kolkata'; d date := (now() at time zone 'Asia/Kolkata')::date; e jsonb; n int := 0;
begin
 if not is_admin() then raise exception 'forbidden'; end if;
 if t::time < time '22:00' or t::time >= time '23:00' then raise exception 'Glory can only be submitted 10-11 PM IST'; end if;
 for e in select * from jsonb_array_elements(entries) loop
  insert into glory_daily(member_id,day,gained,submitted_by) values((e->>'member_id')::uuid,d,(e->>'gained')::int,auth.uid()) on conflict(member_id,day) do nothing;
  if found then
   insert into glory_totals(member_id,weekly) values((e->>'member_id')::uuid,(e->>'gained')::int) on conflict(member_id) do update set weekly=glory_totals.weekly+excluded.weekly;
   n := n+1; end if;
 end loop;
 perform audit('glory_submit',d::text,jsonb_build_object('entries',n)); return n; end $$;

create function correct_glory(p_member uuid,p_day date,p_new int,p_reason text) returns void language plpgsql security definer set search_path=public as $$
declare o int; ws date := date_trunc('week',now() at time zone 'Asia/Kolkata')::date;
begin
 if not is_admin() then raise exception 'forbidden'; end if;
 select gained into o from glory_daily where member_id=p_member and day=p_day;
 if o is null then raise exception 'no entry for that day'; end if;
 update glory_daily set gained=p_new where member_id=p_member and day=p_day;
 if p_day>=ws then update glory_totals set weekly=weekly+(p_new-o) where member_id=p_member;
 else update glory_totals set lifetime=lifetime+(p_new-o) where member_id=p_member; end if;
 insert into glory_corrections(member_id,day,old_value,new_value,reason,corrected_by) values(p_member,p_day,o,p_new,p_reason,auth.uid());
 perform audit('glory_correction',p_member::text,jsonb_build_object('day',p_day,'old',o,'new',p_new,'reason',p_reason)); end $$;

create function missing_glory(p_day date default (now() at time zone 'Asia/Kolkata')::date) returns table(member_id uuid,username text) language sql security definer set search_path=public as $$
 select p.id,p.username from profiles p where is_admin() and p.status='active' and not exists(select 1 from glory_daily d where d.member_id=p.id and d.day=p_day) $$;

create function finalize_week() returns void language plpgsql security definer set search_path=public as $$
declare ws date := date_trunc('week',now() at time zone 'Asia/Kolkata')::date;
begin
 insert into week_runs(week_start) values(ws) on conflict do nothing;
 if not found then return; end if; -- already processed: no duplicates
 insert into glory_weeks(week_start,member_id,total,rank) select ws,member_id,weekly,rank() over(order by weekly desc) from glory_totals;
 update glory_totals set lifetime=lifetime+weekly, weekly=0;
 insert into audit_logs(action,target) values('week_finalized',ws::text); end $$;
revoke execute on function finalize_week() from public,anon,authenticated;
select cron.schedule('finalize-week','30 17 * * 0',$$select public.finalize_week()$$); -- Sun 17:30 UTC = 23:00 IST

-- public aggregate views (rankings)
create view lb_weekly as select p.id member_id,p.username,p.display_name,p.avatar_url,t.weekly glory,rank() over(order by t.weekly desc) rnk from glory_totals t join profiles p on p.id=t.member_id where p.status='active';
create view lb_lifetime as select p.id member_id,p.username,p.display_name,p.avatar_url,(t.lifetime+t.weekly) glory,rank() over(order by t.lifetime+t.weekly desc) rnk from glory_totals t join profiles p on p.id=t.member_id where p.status='active';
create view lb_daily as select p.id member_id,p.username,p.display_name,p.avatar_url,d.gained glory,rank() over(order by d.gained desc) rnk from glory_daily d join profiles p on p.id=d.member_id where d.day=(now() at time zone 'Asia/Kolkata')::date;
create view lb_monthly as select p.id member_id,p.username,p.display_name,p.avatar_url,sum(d.gained)::int glory,rank() over(order by sum(d.gained) desc) rnk from glory_daily d join profiles p on p.id=d.member_id where date_trunc('month',d.day)=date_trunc('month',(now() at time zone 'Asia/Kolkata')::date) group by p.id,p.username,p.display_name,p.avatar_url;
create view guild_stats as select (select count(*) from profiles where status='active') members,(select coalesce(sum(lifetime+weekly),0) from glory_totals) total_glory;
create view public_members as select id,username,display_name,avatar_url,role,joined_at from profiles where status='active';
grant select on lb_weekly,lb_lifetime,lb_daily,lb_monthly,guild_stats,public_members to anon,authenticated;

-- chat + groups
create table conversations(id uuid primary key default gen_random_uuid(), type text not null check(type in('dm','group')), name text, description text, avatar_url text, wallpaper_url text, privacy text default 'private', created_by uuid references profiles, created_at timestamptz default now());
create table conversation_members(conversation_id uuid references conversations on delete cascade, user_id uuid references profiles on delete cascade, role group_role not null default 'member', pinned bool default false, archived bool default false, muted bool default false, last_read_at timestamptz default now(), joined_at timestamptz default now(), primary key(conversation_id,user_id));
create table messages(id uuid primary key default gen_random_uuid(), conversation_id uuid not null references conversations on delete cascade, sender_id uuid not null references profiles, body text, kind text not null default 'text' check(kind in('text','image','video','file','voice')), media_path text, reply_to uuid references messages, forwarded_from uuid references messages, pinned bool default false, edited_at timestamptz, deleted_at timestamptz, created_at timestamptz default now());
create index on messages(conversation_id,created_at);
create index on messages using gin (to_tsvector('simple',coalesce(body,'')));
create table message_reactions(message_id uuid references messages on delete cascade, user_id uuid references profiles on delete cascade, emoji text not null, primary key(message_id,user_id,emoji));
create table blocks(blocker uuid references profiles on delete cascade, blocked uuid references profiles on delete cascade, primary key(blocker,blocked));
create table reports(id uuid primary key default gen_random_uuid(), reporter uuid references profiles, target_type text, target_id text, reason text, status text default 'open', created_at timestamptz default now());
alter table conversations enable row level security; alter table conversation_members enable row level security; alter table messages enable row level security; alter table message_reactions enable row level security; alter table blocks enable row level security; alter table reports enable row level security;

create function is_member(cid uuid) returns boolean language sql stable security definer set search_path=public as $$ select exists(select 1 from conversation_members where conversation_id=cid and user_id=auth.uid()) $$;
create function is_group_admin(cid uuid) returns boolean language sql stable security definer set search_path=public as $$ select is_admin() or exists(select 1 from conversation_members where conversation_id=cid and user_id=auth.uid() and role in('owner','admin')) $$;

create policy c_sel on conversations for select to authenticated using (is_member(id) or (type='group' and is_admin()));
create policy c_upd on conversations for update to authenticated using (type='group' and is_group_admin(id));
-- no insert policy: groups only via create_group() (admins), DMs via get_or_create_dm()
create policy cm_sel on conversation_members for select to authenticated using (is_member(conversation_id) or is_admin());
create policy cm_upd on conversation_members for update to authenticated using (user_id=auth.uid() or is_group_admin(conversation_id));
create policy cm_ins on conversation_members for insert to authenticated with check (is_group_admin(conversation_id) and exists(select 1 from conversations where id=conversation_id and type='group'));
create policy cm_del on conversation_members for delete to authenticated using (user_id=auth.uid() or is_group_admin(conversation_id));
create function guard_member() returns trigger language plpgsql security definer set search_path=public as $$
begin if new.role<>old.role and not is_group_admin(new.conversation_id) then raise exception 'forbidden'; end if; return new; end $$;
create trigger t_guard_member before update on conversation_members for each row execute function guard_member();

create policy m_sel on messages for select to authenticated using (is_member(conversation_id));
create policy m_ins on messages for insert to authenticated with check (sender_id=auth.uid() and is_active() and is_member(conversation_id));
create policy m_upd on messages for update to authenticated using (sender_id=auth.uid() or is_group_admin(conversation_id));
create function message_guard() returns trigger language plpgsql security definer set search_path=public as $$
begin
 if tg_op='INSERT' then
  if (select count(*) from messages where sender_id=new.sender_id and created_at>now()-interval '10 seconds')>=15 then raise exception 'Slow down'; end if;
  if exists(select 1 from conversations c join conversation_members m on m.conversation_id=c.id and m.user_id<>new.sender_id join blocks b on (b.blocker=m.user_id and b.blocked=new.sender_id) or (b.blocker=new.sender_id and b.blocked=m.user_id) where c.id=new.conversation_id and c.type='dm') then raise exception 'Blocked'; end if;
 else
  if new.sender_id<>old.sender_id or new.conversation_id<>old.conversation_id then raise exception 'immutable'; end if;
  if auth.uid()<>old.sender_id and (new.body is distinct from old.body or new.deleted_at is distinct from old.deleted_at) then raise exception 'forbidden'; end if;
 end if; return new; end $$;
create trigger t_msg_guard before insert or update on messages for each row execute function message_guard();
create policy mr_sel on message_reactions for select to authenticated using (exists(select 1 from messages m where m.id=message_id and is_member(m.conversation_id)));
create policy mr_ins on message_reactions for insert to authenticated with check (user_id=auth.uid() and exists(select 1 from messages m where m.id=message_id and is_member(m.conversation_id)));
create policy mr_del on message_reactions for delete to authenticated using (user_id=auth.uid());
create policy b_all on blocks for all to authenticated using (blocker=auth.uid()) with check (blocker=auth.uid());
create policy r_ins on reports for insert to authenticated with check (reporter=auth.uid());
create policy r_sel on reports for select to authenticated using (is_mod());
create policy r_upd on reports for update to authenticated using (is_mod());

create function create_group(p_name text,p_desc text,p_privacy text,p_members uuid[],p_admins uuid[]) returns uuid language plpgsql security definer set search_path=public as $$
declare cid uuid; u uuid;
begin
 if not is_admin() then raise exception 'Only administrators can create groups'; end if;
 insert into conversations(type,name,description,privacy,created_by) values('group',p_name,p_desc,coalesce(p_privacy,'private'),auth.uid()) returning id into cid;
 insert into conversation_members(conversation_id,user_id,role) values(cid,auth.uid(),'owner');
 foreach u in array coalesce(p_members,'{}') loop
  if u<>auth.uid() then insert into conversation_members(conversation_id,user_id,role) values(cid,u,case when u=any(coalesce(p_admins,'{}')) then 'admin'::group_role else 'member'::group_role end) on conflict do nothing; end if;
 end loop;
 perform audit('group_create',cid::text,jsonb_build_object('name',p_name)); return cid; end $$;
create function get_or_create_dm(other uuid) returns uuid language plpgsql security definer set search_path=public as $$
declare cid uuid;
begin
 if not is_active() or other=auth.uid() then raise exception 'not allowed'; end if;
 select c.id into cid from conversations c where c.type='dm' and exists(select 1 from conversation_members m where m.conversation_id=c.id and m.user_id=auth.uid()) and exists(select 1 from conversation_members m where m.conversation_id=c.id and m.user_id=other) limit 1;
 if cid is null then
  insert into conversations(type,created_by) values('dm',auth.uid()) returning id into cid;
  insert into conversation_members(conversation_id,user_id) values(cid,auth.uid()),(cid,other);
 end if; return cid; end $$;

-- notifications
create table notifications(id uuid primary key default gen_random_uuid(), user_id uuid not null references profiles on delete cascade, type text not null, title text, body text, link text, read bool default false, created_at timestamptz default now());
create table notification_prefs(user_id uuid primary key references profiles on delete cascade, prefs jsonb default '{}', sound bool default false);
alter table notifications enable row level security; alter table notification_prefs enable row level security;
create policy n_sel on notifications for select to authenticated using (user_id=auth.uid());
create policy n_upd on notifications for update to authenticated using (user_id=auth.uid());
create policy np_all on notification_prefs for all to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());
create function on_message() returns trigger language plpgsql security definer set search_path=public as $$
begin
 insert into notifications(user_id,type,title,body,link) select m.user_id,case when c.type='dm' then 'message' else 'group_message' end,coalesce(c.name,'New message'),left(coalesce(new.body,'['||new.kind||']'),80),'/chat?c='||c.id from conversation_members m join conversations c on c.id=m.conversation_id where m.conversation_id=new.conversation_id and m.user_id<>new.sender_id and not m.muted;
 return new; end $$;
create trigger t_on_message after insert on messages for each row execute function on_message();
create function on_group_add() returns trigger language plpgsql security definer set search_path=public as $$
begin if new.user_id<>auth.uid() and exists(select 1 from conversations where id=new.conversation_id and type='group') then
 insert into notifications(user_id,type,title,link) values(new.user_id,'group_add','You were added to a group','/chat?c='||new.conversation_id); end if; return new; end $$;
create trigger t_on_group_add after insert on conversation_members for each row execute function on_group_add();

-- announcements
create table announcements(id uuid primary key default gen_random_uuid(), title text not null, body text, category text, pinned bool default false, comments_enabled bool default true, publish_at timestamptz default now(), author_id uuid references profiles, created_at timestamptz default now());
create table announcement_reads(announcement_id uuid references announcements on delete cascade, user_id uuid references profiles on delete cascade, primary key(announcement_id,user_id));
create table announcement_reactions(announcement_id uuid references announcements on delete cascade, user_id uuid references profiles on delete cascade, emoji text, primary key(announcement_id,user_id,emoji));
create table announcement_comments(id uuid primary key default gen_random_uuid(), announcement_id uuid references announcements on delete cascade, user_id uuid references profiles, body text not null, created_at timestamptz default now());
alter table announcements enable row level security; alter table announcement_reads enable row level security; alter table announcement_reactions enable row level security; alter table announcement_comments enable row level security;
create policy a_sel on announcements for select using (publish_at<=now() or is_admin());
create policy a_adm on announcements for all to authenticated using (is_admin()) with check (is_admin());
create policy ar_all on announcement_reads for all to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());
create policy arx_sel on announcement_reactions for select to authenticated using (true);
create policy arx_w on announcement_reactions for all to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());
create policy ac_sel on announcement_comments for select to authenticated using (true);
create policy ac_ins on announcement_comments for insert to authenticated with check (user_id=auth.uid() and is_active() and exists(select 1 from announcements a where a.id=announcement_id and a.comments_enabled));
create policy ac_del on announcement_comments for delete to authenticated using (user_id=auth.uid() or is_mod());
create function on_announcement() returns trigger language plpgsql security definer set search_path=public as $$
begin if new.publish_at<=now() then insert into notifications(user_id,type,title,link) select id,'announcement',new.title,'/announcements' from profiles where status='active'; end if; return new; end $$;
create trigger t_on_announcement after insert on announcements for each row execute function on_announcement();

-- polls
create table polls(id uuid primary key default gen_random_uuid(), question text not null, options jsonb not null, status text not null default 'suggested' check(status in('suggested','rejected','open','closed')), anonymous bool default false, results_public bool default false, deadline timestamptz, created_by uuid references profiles, created_at timestamptz default now());
create table poll_votes(poll_id uuid references polls on delete cascade, user_id uuid references profiles on delete cascade, option_idx int not null, created_at timestamptz default now(), primary key(poll_id,user_id));
alter table polls enable row level security; alter table poll_votes enable row level security;
create policy po_sel on polls for select to authenticated using (status in('open','closed') or created_by=auth.uid() or is_admin());
create policy po_sug on polls for insert to authenticated with check (created_by=auth.uid() and status='suggested' and is_active());
create policy po_adm on polls for all to authenticated using (is_admin()) with check (is_admin());
create policy pv_sel on poll_votes for select to authenticated using (user_id=auth.uid() or is_admin());
create policy pv_ins on poll_votes for insert to authenticated with check (user_id=auth.uid() and is_active() and exists(select 1 from polls p where p.id=poll_id and p.status='open' and (p.deadline is null or p.deadline>now())));
-- no update/delete policy on votes: one vote, cannot be changed
create function poll_results(pid uuid) returns table(option_idx int,votes bigint) language sql security definer set search_path=public as $$
 select v.option_idx,count(*) from poll_votes v join polls p on p.id=v.poll_id where v.poll_id=pid and (p.results_public or is_admin()) group by v.option_idx $$;

-- events
create table events(id uuid primary key default gen_random_uuid(), title text not null, description text, kind text default 'event', starts_at timestamptz, results jsonb, winners jsonb, created_by uuid references profiles, created_at timestamptz default now());
create table event_rooms(event_id uuid primary key references events on delete cascade, room_id text, room_password text, visible bool default false);
create table event_registrations(event_id uuid references events on delete cascade, user_id uuid references profiles on delete cascade, created_at timestamptz default now(), primary key(event_id,user_id));
alter table events enable row level security; alter table event_rooms enable row level security; alter table event_registrations enable row level security;
create policy e_sel on events for select using (true);
create policy e_adm on events for all to authenticated using (is_admin()) with check (is_admin());
create policy er_sel on event_rooms for select to authenticated using (is_admin() or (visible and exists(select 1 from event_registrations r where r.event_id=event_rooms.event_id and r.user_id=auth.uid())));
create policy er_adm on event_rooms for all to authenticated using (is_admin()) with check (is_admin());
create policy reg_sel on event_registrations for select to authenticated using (true);
create policy reg_ins on event_registrations for insert to authenticated with check (user_id=auth.uid() and is_active());
create policy reg_del on event_registrations for delete to authenticated using (user_id=auth.uid());

-- badges
create table badges(id serial primary key, code text unique, name text not null, description text);
create table member_badges(member_id uuid references profiles on delete cascade, badge_id int references badges, awarded_by uuid references profiles, awarded_at timestamptz default now(), primary key(member_id,badge_id,awarded_at));
alter table badges enable row level security; alter table member_badges enable row level security;
create policy bd_sel on badges for select using (true);
create policy bd_adm on badges for all to authenticated using (is_admin()) with check (is_admin());
create policy mb_sel on member_badges for select to authenticated using (true);
create policy mb_adm on member_badges for all to authenticated using (is_admin()) with check (is_admin());
insert into badges(code,name) values('glory_champion','Glory Champion'),('weekly_mvp','Weekly MVP'),('most_active','Most Active'),('tournament_winner','Tournament Winner'),('guild_veteran','Guild Veteran'),('top_contributor','Top Contributor'),('founding_member','Founding Member');

-- activity
create table login_history(id bigint generated always as identity primary key, user_id uuid not null references profiles on delete cascade, device text, browser text, os text, created_at timestamptz default now());
alter table login_history enable row level security;
create policy lh_ins on login_history for insert to authenticated with check (user_id=auth.uid());
create policy lh_sel on login_history for select to authenticated using (user_id=auth.uid() or is_admin());

-- recruitment
create table applications(id uuid primary key default gen_random_uuid(), applicant_id uuid not null references profiles, ff_ign text not null, ff_uid text not null, level int, ff_rank text, current_guild text, game_mode text, experience text, intro text, status text not null default 'pending' check(status in('pending','info_requested','approved','rejected')), admin_note text, reviewed_by uuid references profiles, created_at timestamptz default now());
create unique index one_open_app on applications(applicant_id) where status in('pending','info_requested');
alter table applications enable row level security;
create policy ap_ins on applications for insert to authenticated with check (applicant_id=auth.uid() and status='pending');
create policy ap_sel on applications for select to authenticated using (applicant_id=auth.uid() or is_admin());
create function review_application(p_id uuid,p_decision text,p_note text) returns void language plpgsql security definer set search_path=public as $$
declare a applications;
begin
 if not is_admin() then raise exception 'forbidden'; end if;
 if p_decision not in('approved','rejected','info_requested') then raise exception 'bad decision'; end if;
 update applications set status=p_decision,admin_note=p_note,reviewed_by=auth.uid() where id=p_id returning * into a;
 if p_decision='approved' then update profiles set status='active',ff_ign=a.ff_ign,ff_uid=a.ff_uid,player_level=a.level,ff_rank=a.ff_rank where id=a.applicant_id; end if;
 perform audit('application_'||p_decision,p_id::text,null); end $$;

-- moderation
create table mod_actions(id uuid primary key default gen_random_uuid(), target_id uuid references profiles, action text, reason text, until timestamptz, by uuid references profiles, created_at timestamptz default now());
create table admin_notes(id uuid primary key default gen_random_uuid(), target_id uuid references profiles, note text, by uuid references profiles, created_at timestamptz default now());
alter table mod_actions enable row level security; alter table admin_notes enable row level security;
create policy ma_sel on mod_actions for select to authenticated using (is_mod() or target_id=auth.uid());
create policy an_all on admin_notes for all to authenticated using (is_mod()) with check (is_mod());
create function moderate_user(p_target uuid,p_action text,p_reason text,p_until timestamptz default null) returns void language plpgsql security definer set search_path=public as $$
begin
 if p_action='warn' then if not is_mod() then raise exception 'forbidden'; end if;
 elsif not is_admin() then raise exception 'forbidden'; end if;
 if (select role from profiles where id=p_target) in('admin','super_admin') and my_role()<>'super_admin' then raise exception 'cannot moderate admins'; end if;
 if p_action='suspend' then update profiles set status='suspended',banned_until=p_until where id=p_target;
 elsif p_action='ban' then update profiles set status='banned',banned_until=p_until where id=p_target;
 elsif p_action='unban' then update profiles set status='active',banned_until=null where id=p_target; end if;
 insert into mod_actions(target_id,action,reason,until,by) values(p_target,p_action,p_reason,p_until,auth.uid());
 perform audit('mod_'||p_action,p_target::text,jsonb_build_object('reason',p_reason)); end $$;

-- settings + music
create table site_settings(key text primary key, value jsonb, updated_at timestamptz default now());
create table music_tracks(id uuid primary key default gen_random_uuid(), title text not null, path text not null, uploaded_by uuid references profiles, created_at timestamptz default now());
create table user_prefs(user_id uuid primary key references profiles on delete cascade, music jsonb default '{}', dashboard jsonb default '{}');
alter table site_settings enable row level security; alter table music_tracks enable row level security; alter table user_prefs enable row level security;
create policy ss_sel on site_settings for select using (true);
create policy ss_adm on site_settings for all to authenticated using (is_admin()) with check (is_admin());
create policy mt_sel on music_tracks for select using (true);
create policy mt_adm on music_tracks for all to authenticated using (is_admin()) with check (is_admin());
create policy up_all on user_prefs for all to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());
insert into site_settings values('guild_name','"SYMBIOTES"',now()),('recruitment_open','true',now()),('maintenance','false',now());

-- storage
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types) values
('avatars','avatars',true,5242880,array['image/jpeg','image/png','image/webp']),
('chat-media','chat-media',false,52428800,array['image/*','video/*','audio/*','application/pdf','text/plain','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document']),
('music','music',true,20971520,array['audio/*']),
('site','site',true,5242880,array['image/*']);
create policy st_av_w on storage.objects for all to authenticated using (bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text) with check (bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text);
create policy st_pub_r on storage.objects for select using (bucket_id in('avatars','music','site'));
create policy st_adm_w on storage.objects for all to authenticated using (bucket_id in('music','site') and is_admin()) with check (bucket_id in('music','site') and is_admin());
create policy st_chat_r on storage.objects for select to authenticated using (bucket_id='chat-media' and is_member(((storage.foldername(name))[1])::uuid));
create policy st_chat_w on storage.objects for insert to authenticated with check (bucket_id='chat-media' and is_active() and is_member(((storage.foldername(name))[1])::uuid));

-- realtime
alter publication supabase_realtime add table messages,message_reactions,notifications,conversation_members,announcements,polls;

-- AFTER signing up, make yourself super admin (run once, replace email):
-- update profiles set role='super_admin',status='active' where id=(select id from auth.users where email='YOU@EXAMPLE.COM');
