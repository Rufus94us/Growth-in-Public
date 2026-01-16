---
description: supabase-database@2025-01-21
globs: ["**/*.sql", "**/*.ts", "**/*.json"]
alwaysApply: true
---

You are an expert in Supabase and PostgreSQL security best practices.

**🔒 SÉCURITÉ SUPABASE :**
- **RLS activé** sur toutes les tables + politique utilisant helper JWT (`user_id = public.jwt_user_id()`)
- **Policies RLS** : `TO authenticated` (par défaut) ; remplacer `auth.uid()` par `public.jwt_user_id()` dans toutes les policies, vues et triggers qui lisent des tables RLS (évite erreurs `permission denied for schema auth`)
- **FORCE ROW LEVEL SECURITY** sur toutes les tables multi-tenant (évite bypass accidentel) - les opérations cross-user passent par Edge + service_role → RPC INVOKER ; service_role bypasse RLS, FORCE RLS protège tout le reste
- **UUID** pour les clés primaires, **FK obligatoires** pour les relations
- **Credentials** via secrets manager ou Supabase secrets (jamais en dur)
- **Edge Functions par défaut** pour toute opération cross-user / sensible (quotas, files, exports, agrégats) ; accès direct PostgREST/RPC réservé aux opérations user-scopées simples
- **Rôle `function_owner`** avec permissions minimales pour posséder toutes les fonctions SQL (RPC et triggers) - principe du moindre privilège

**⚡ TRIGGERS SQL - RÈGLES CRITIQUES :**
- **TOUJOURS utiliser SECURITY INVOKER** pour les fonctions de trigger (jamais SECURITY DEFINER)
- **Les triggers respectent la RLS** exactement comme l'ordre DML qui les déclenche
- **COALESCE(field, 0)** pour éviter NULL en arithmétique
- **Politique UPDATE** USING/WITH CHECK (true) pour RLS
- **Debug via table debug_logs** (pas RAISE NOTICE)
- **format() correct :** %L (literal), %I (identifier)
- **Vérifier trigger ENABLED** + vraie modification de valeur
- **Accès cross-tables RLS :**
  - Exprimer l'accès via des policies RLS ciblées (USING / WITH CHECK) sur les tables concernées
  - Si ce n'est pas modélisable proprement, déplacer la logique hors trigger (RPC appelée depuis l'Edge avec service_role)
  - Si non faisable, refuser l'implémentation (fail fast)
- **Garde-fous conseillés** (comme le DML tourne souvent via service_role) :
  - `workspace_id` obligatoire et immuable à l'UPDATE
  - Toutes les requêtes depuis le trigger filtrent par `workspace_id`

**🔐 FONCTIONS SQL - STANDARD DE SÉCURISATION OBLIGATOIRE :**
- **Header de modification :** `-- Modified: DD/MM/YYYY HH:MM:SS - [FICHIER] - Sécurisation standard`
- **DROP FUNCTION IF EXISTS** avec signature complète avant recréation
- **TOUJOURS utiliser SECURITY INVOKER** pour toutes les fonctions RPC (exécution avec droits appelant + RLS)
- **Pour cas cross-user** : utiliser le pattern Edge Function → service_role → RPC INVOKER (voir section dédiée)
- **SET search_path = pg_catalog, public** obligatoire (chemin stable, évite injections, évite résolution "magique")
- **Tables qualifiées** (`public.table_name`) dans toutes les fonctions
- **Validation des entrées stricte (centralisée) :**
  - Vérifier paramètres NULL obligatoires (rejeter NULL inattendus immédiatement)
  - Valider bornes numériques (ex: limites 1-1000)
  - Valider format UUID avec regex `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
  - Valider tailles max d'array (cardinality(p_ids) <= 1000)
- **Helper JWT pour user_id** : utiliser `public.jwt_user_id()` ou `current_setting('request.jwt.claims')` au lieu de `auth.uid()` (évite erreurs `permission denied for schema auth`)
- **Vérification de propriété** pour données user-scoped : charger `v_user_id` depuis JWT et utiliser dans filtres (`WHERE l.user_id = v_user_id`)
- **Ownership et permissions strictes (Allow-list d'exécution RPC) :**
  - `ALTER FUNCTION nom_fonction(paramètres) OWNER TO function_owner` (obligatoire - principe du moindre privilège)
  - `REVOKE ALL ON FUNCTION nom_fonction(paramètres) FROM PUBLIC`
  - **Aucune RPC n'a de GRANT global.** Chaque RPC appartient à un des deux types :
    - **(a) user-scoped** → `GRANT EXECUTE ON FUNCTION nom_fonction(paramètres) TO authenticated` uniquement (fonction par fonction, pas de GRANT globaux) - INVOCATEUR + RLS
    - **(b) cross-user** → `GRANT EXECUTE ON FUNCTION nom_fonction(paramètres) TO service_role` uniquement - appelée UNIQUEMENT depuis Edge
  - ❌ **PAS de GRANT à anon** (sauf cas spécifique documenté)

**🔍 PATTERN RECOMMANDÉ - CROSS-USER DEPUIS FRONT :**
- **✅ Pattern obligatoire :** Front → Edge Function → service_role → RPC en SECURITY INVOKER
  - **Pourquoi créer une Edge Function ?** Les RPC cross-user nécessitent `service_role` pour bypass RLS, mais ne doivent jamais être appelées directement depuis le front (sécurité). L'Edge vérifie l'auth utilisateur puis appelle la RPC avec `service_role`.
  - **Front** : Envoie le JWT utilisateur à l'Edge Function
  - **Edge Function** : 
    - Vérifie authentification (`await supabaseClient.auth.getUser()`)
    - Vérifie autorisation (rôle, tenant, limites applicatives) - **Optionnel :** `ADMIN_USER_IDS` (secret Supabase, CSV d'UUIDs) pour restreindre aux admins uniquement
    - Log les actions (audit)
    - Crée un client avec `service_role` pour appeler la RPC
  - **RPC** : Reste en `SECURITY INVOKER`, mais réservée à `service_role` uniquement
    - Quand l'Edge appelle avec `service_role`, la RPC s'exécute avec les droits de `service_role` → bypass RLS automatique
    - `FORCE RLS` reste actif sur les tables (protège tout le reste), mais `service_role` passe quand même
    - **Pas besoin de lire JWT dans la RPC** (inutile côté système, l'Edge gère l'auth)

- **Migration :** Prévoir une passe de migration des appels RPC cross-user depuis le front vers Edge Functions (les appels sensibles ne doivent plus être faits directement depuis le front)

**Checklist obligatoire par fonction RPC :**
- [ ] `DROP FUNCTION IF EXISTS` avec signature complète
- [ ] **SECURITY INVOKER** (toujours)
- [ ] `SET search_path = pg_catalog, public` ajouté
- [ ] Tables qualifiées (`public.table_name`)
- [ ] **Si RPC réservée à service_role (pattern cross-user)** :
  - Pas de lecture JWT dans la RPC (l'Edge gère l'auth)
  - Validation des entrées (NULL, bornes, formats UUID)
  - `REVOKE ALL ON FUNCTION ... FROM PUBLIC`
  - `GRANT EXECUTE ON FUNCTION ... TO service_role` uniquement (pas authenticated)
- [ ] **Si RPC standard (user-scoped)** :
  - Utilisation helper JWT (`public.jwt_user_id()` ou `current_setting('request.jwt.claims')`) au lieu de `auth.uid()`
  - Validation des entrées (NULL, bornes, formats)
  - Vérification propriété avec `v_user_id` depuis JWT
  - `REVOKE ALL ON FUNCTION ... FROM PUBLIC`
  - `GRANT EXECUTE ON FUNCTION ... TO authenticated` uniquement
- [ ] `OWNER TO function_owner` (obligatoire - principe du moindre privilège)
- [ ] **Budget de sortie et pagination forcée (anti-exfiltration)** : Toute RPC qui retourne des lignes doit imposer `limit <= 1000` (ex : `if p_limit > 1000 then raise exception`), et toujours demander `offset`. Pour gros volumes, utiliser **Keyset/Cursor-based** (scalable, recommandée) : le client (Edge) passe le curseur (`after_created_at`, `after_id`) reçu de la page précédente → pas d'offset (meilleure perf). Pour exports, exiger un filtre obligatoire (dates/tenant/ressource)
- [ ] **Limiter l'exécution** : `SET LOCAL statement_timeout = '15s'; SET LOCAL idle_in_transaction_session_timeout = '5s';` pour les RPC lourdes (list/export)

**🏗️ ARCHITECTURE MULTI-TENANT :**
- **Isolation par client** avec RLS Supabase
- **FORCE ROW LEVEL SECURITY** sur toutes les tables multi-tenant qui n'ont pas besoin d'accès cross-tenant (données métier, queues, todos, archived_*, logs, etc.)
- **Data flow :** Frontend → Supabase Functions → Webhooks externes
- **Cache** toutes les API responses dans Supabase
- **Variables d'environnement** + rate limiting + audit logs

**🚀 EDGE FUNCTIONS - STANDARD D'AUTHENTIFICATION OBLIGATOIRE :**
- **Edge Functions par défaut** pour toute opération cross-user / sensible (quotas, files, exports, agrégats) ; accès direct PostgREST/RPC réservé aux opérations user-scopées simples
- **Pattern standard (user-scoped)** :
  - **TOUJOURS utiliser ANON_KEY + token utilisateur** (PAS service_role)
  - **Vérification authentification obligatoire :** `await supabaseClient.auth.getUser()` → 401 si non authentifié
  - **Validation des paramètres :** Vérifier paramètres manquants → 400
  - **Vérification propriété :** `if (body.userId !== user.id)` → 403 si userId différent du token
  - **Pattern obligatoire :** `createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { global: { headers: { Authorization } } })`
- **Couches Edge (sécurité) :**
  - **Rate-limit** (clé = user.id + endpoint) - limiter les appels par utilisateur et endpoint
  - **Audit minimal** : `public.security_audit_logs(user_id, action, function_name, ok, error_message, ip)` pour chaque appel cross-user - renvoyer les logs de la Edge Function dans cette table
  - **Masquage d'erreurs** : ne jamais renvoyer de messages SQL bruts (masquer les détails techniques)
  - **CORS/Headers** : CORS restreint (origins de prod uniquement), CSP stricte, `X-Content-Type-Options: nosniff`, pas de `cache-control: public` sur endpoints sensibles
  - **Interdit** : ne jamais faire `.from('table')` avec service_role côté Edge pour de la logique métier — toujours appeler une RPC allow-listée
- **Pattern cross-user (nécessite bypass RLS)** :
  - **Front** : Envoie le JWT utilisateur à l'Edge Function
  - **Edge Function (première partie - vérification)** :
    - Utilise `ANON_KEY + token utilisateur` pour vérifier l'auth
    - `await supabaseClient.auth.getUser()` → 401 si non authentifié
    - Vérifie autorisation applicative (rôle admin, ownership workspace, limites)
    - **Restriction admin optionnelle :** Si l'Edge doit être réservée aux admins uniquement, utiliser `ADMIN_USER_IDS` (secret Supabase, CSV d'UUIDs) : `if (adminIds.length > 0 && !adminIds.includes(user.id)) return 403`
    - Log l'action dans `public.security_audit_logs` (audit)
    - Validation des paramètres → 400 si manquants
  - **Edge Function (deuxième partie - appel RPC)** :
    - Crée un client avec `SUPABASE_SERVICE_ROLE_KEY` pour appeler la RPC
    - `const adminClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)`
    - Appelle la RPC : `await adminClient.rpc('nom_fonction', params)`
    - La RPC est en `SECURITY INVOKER` mais réservée à `service_role` → s'exécute avec droits service_role → bypass RLS
  - **RPC** : En `SECURITY INVOKER`, réservée à `service_role` uniquement (voir section "Pattern recommandé")
- **Gestion refresh_token pour processus longs :**
  - Stocker `refresh_token` (durée 60 jours) dans les détails du processus au lieu de `access_token` (durée 1h)
  - Regénérer `access_token` via `auth.refreshSession()` dans les callbacks pour processus > 1h

**📁 EDGE FUNCTIONS - NOMMAGE OBLIGATOIRE :**
- **Nommage explicite obligatoire :** Le nom du fichier doit décrire clairement l'utilisation de la fonction
- **Format de nommage :** Utiliser des noms en minuscules, séparés par des tirets (`-`), décrivant l'action principale de la fonction
- **Exemples de nommage correct :**
  - `refresh-analytics-views.ts` - Rafraîchit les vues analytiques
  - `start-process.ts` - Démarre un processus
  - `process-queue.ts` - Traite une queue
  - `check-quotas.ts` - Vérifie les quotas utilisateur
  - `export-csv.ts` - Exporte des données en CSV
- **Interdictions :**
  - ❌ Noms génériques ou vagues (`function.ts`, `handler.ts`, `api.ts`)
  - ❌ Noms sans tirets ou avec underscores (`refresh_analytics.ts` → utiliser `refresh-analytics.ts`)
  - ❌ Noms qui ne décrivent pas l'action (`data.ts`, `utils.ts`)

**🛡️ ERROR HANDLING :**
- Log automation failures dans Supabase audit tables
- **Table `public.security_audit_logs`** pour monitoring post-déploiement (function_name, user_id, action, success, error_message) - lecture admin/service uniquement
- Retry automatique pour failures temporaires
- Notification admin pour failures critiques
- Queues séparées par type d'intégration

**⚡ REALTIME UI BEST PRACTICES :**
- Après `setQueryData` optimiste dans les hooks Realtime, toujours appeler `queryClient.invalidateQueries` pour forcer le re-render de l'UI.
- Utiliser un flag `isUnmounting` dans useEffect pour ignorer les événements 'CLOSED' pendant le cleanup des channels Supabase et éviter des invalidations inutiles.
- Ajouter `refetchOnMount: 'always'` dans useQuery pour forcer maj quand on revient sur la page (utile si channel unsub pendant navigation).
- Pour listes dynamiques, persister le listening Realtime même hors page pour capturer updates en background, avec cleanup safe.
- **Sécurité Realtime :**
  - Interdire les channels "larges" (sans filtres). Toujours filtrer par `user_id` (et éventuellement un scope métier)
  - Fallback polling si channel en erreur (évite reconnections agressives)

**🔧 CI DE SÉCURITÉ SQL :**
- **Lint automatique** cherchant :
  - `auth.uid()` (doit être `jwt_user_id()`)
  - `search_path` manquant (doit être `SET search_path = pg_catalog, public`)
  - `GRANT` publics (pas de GRANT à PUBLIC)
  - `SELECT *` (toujours spécifier les colonnes)
  - `LIMIT` manquant (toujours limiter les résultats)
- **Test snapshot des GRANTs** : fail si une RPC obtient accidentellement `authenticated` alors qu'elle devrait être réservée à `service_role` uniquement
- **Vérifier les GRANT de chaque RPC** : fail si une RPC n'a ni `GRANT ... TO authenticated` ni `GRANT ... TO service_role` (pour éviter qu'une RPC reste appelée par accident via PUBLIC ou sans GRANT explicite)

**📋 GUARDRAIL :**
Si demande manque de contexte → demander clarification avant implémentation