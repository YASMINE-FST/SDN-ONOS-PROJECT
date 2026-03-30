"""
IDS ONOS — Visualisation complète + Entraînement + Validation
Pipeline : EDA → Corrélations → Training RF/XGB/DT → Cross-val → Export modèles
Compatible sklearn 0.24+ / 1.x / 1.8+
"""
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import matplotlib.patches as mpatches
from matplotlib.colors import LinearSegmentedColormap
import seaborn as sns
import warnings, json, joblib, os, time
warnings.filterwarnings("ignore")

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import (train_test_split, StratifiedKFold,
                                      cross_validate, learning_curve)
from sklearn.metrics import (classification_report, confusion_matrix,
                              f1_score, precision_score, recall_score,
                              accuracy_score)
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.feature_selection import f_classif
from xgboost import XGBClassifier
import inspect

# ─── TSNE kwargs compat (sklearn 0.24 / 1.0 / 1.1 / 1.2+) ───
def _tsne_compat(**base_kw):
    """Retourne TSNE avec les bons kwargs selon la version installée."""
    sig = inspect.signature(TSNE.__init__)
    params = sig.parameters
    extra = {}
    if "max_iter" in params:
        extra["max_iter"] = 500
    elif "n_iter" in params:
        extra["n_iter"] = 500
    return TSNE(**base_kw, **extra)

# ═══════════════════════════ CONFIG ═══════════════════════════
BG, BG2, GRID = "#0d1117", "#161b22", "#21262d"
TEXT, TEXT2, ACCENT = "#e6edf3", "#8b949e", "#58a6ff"

COLOR_MAP = {
    "BENIGN":"#3fb950","ARP_SPOOFING":"#ff7b72","STP_SPOOFING":"#d2a8ff",
    "MAC_FLOODING":"#f85149","DHCP_SPOOFING":"#ffa657","IP_SPOOFING":"#ff6eb4",
    "SYN_FLOOD":"#ff4444","DDOS":"#da3633","PORT_SCAN":"#79c0ff",
    "ROUTING_ATTACK":"#39d3dd","SQL_INJECTION":"#c9a96e","XSS":"#94a3b8",
    "SSL_STRIPPING":"#f0c000","SESSION_HIJACKING":"#818cf8",
}
LABEL_ORDER = [
    "ARP_SPOOFING", "BENIGN", "DDOS", "DHCP_SPOOFING", "IP_SPOOFING",
    "MAC_FLOODING", "PORT_SCAN", "ROUTING_ATTACK", "STP_SPOOFING", "SYN_FLOOD",
]
MCOLS = ["#58a6ff","#ffa657","#3fb950"]
os.makedirs("outputs", exist_ok=True)

def style_ax(ax, title="", xlabel="", ylabel=""):
    ax.set_facecolor(BG2)
    ax.tick_params(colors=TEXT2, labelsize=8)
    for spine in ax.spines.values(): spine.set_color(GRID)
    ax.xaxis.label.set_color(TEXT2); ax.yaxis.label.set_color(TEXT2)
    if title:  ax.set_title(title,  color=TEXT, fontsize=10, fontweight="bold", pad=8)
    if xlabel: ax.set_xlabel(xlabel, color=TEXT2, fontsize=8)
    if ylabel: ax.set_ylabel(ylabel, color=TEXT2, fontsize=8)
    ax.grid(color=GRID, linewidth=0.5, alpha=0.7)

# ═══════════════════════════ LOAD ═══════════════════════════
print("Loading dataset...")
df = pd.read_csv("dataset/hybrid_dataset.csv")
FEATURE_COLS = [c for c in df.columns if c not in ["label","label_encoded"]]
le = LabelEncoder(); le.fit(LABEL_ORDER)
df["label_enc"] = le.transform(df["label"])
X = df[FEATURE_COLS].values; y = df["label_enc"].values
import sklearn; print(f"  {len(df)} flows · {len(FEATURE_COLS)} features · {len(LABEL_ORDER)} classes  [sklearn {sklearn.__version__}]")

DISC = ["flow_pkts_per_sec","flow_iat_mean","syn_flag_count","unique_src_mac",
        "arp_reply_ratio","bcast_ratio","dhcp_offer_count","stp_bpdu_count",
        "has_sql_keyword","has_script_tag","ssl_version_num","session_reuse_ratio",
        "pkt_len_mean","down_up_ratio","http_entropy"]

# ═══════════════════════════ FIG 1 — VISUALISATION ═══════════════════════════
print("\nBuilding Fig 1 — Visualisation & Corrélations...")
fig1 = plt.figure(figsize=(24, 20), facecolor=BG)
gs1  = gridspec.GridSpec(3, 3, figure=fig1, hspace=0.44, wspace=0.35,
                          left=0.06, right=0.97, top=0.93, bottom=0.06)

# 1a — Distribution des classes
ax = fig1.add_subplot(gs1[0, 0])
vc = df["label"].value_counts().reindex(LABEL_ORDER).dropna()
colors = [COLOR_MAP[l] for l in vc.index]
bars = ax.barh(range(len(vc)), vc.values, color=colors, height=0.7, edgecolor="none")
ax.set_yticks(range(len(vc)))
ax.set_yticklabels(vc.index, color=TEXT2, fontsize=7)
for i,(bar,v) in enumerate(zip(bars,vc.values)):
    ax.text(v+30, i, str(v), va="center", color=TEXT2, fontsize=7)
ax.set_xlim(0,6200); ax.yaxis.set_tick_params(length=0)
style_ax(ax, "Distribution des classes", "Flows")

# 1b — Correlation matrix
ax = fig1.add_subplot(gs1[0, 1:])
corr = df[DISC].corr()
cmap_rg = LinearSegmentedColormap.from_list("rg",["#da3633","#21262d","#3fb950"])
mask_u  = np.triu(np.ones_like(corr, dtype=bool), k=1)
sns.heatmap(corr, ax=ax, cmap=cmap_rg, mask=mask_u, vmin=-1, vmax=1,
            linewidths=0.3, linecolor=GRID,
            annot=True, fmt=".2f", annot_kws={"size":6.5,"color":TEXT},
            cbar_kws={"shrink":0.8})
ax.set_facecolor(BG2); ax.tick_params(colors=TEXT2, labelsize=7)
ax.set_title("Matrice de corrélation — features discriminantes",
             color=TEXT, fontsize=10, fontweight="bold", pad=8)
ax.set_xticklabels(ax.get_xticklabels(), rotation=40, ha="right", fontsize=7, color=TEXT2)
ax.set_yticklabels(ax.get_yticklabels(), rotation=0, fontsize=7, color=TEXT2)
ax.collections[0].colorbar.ax.tick_params(colors=TEXT2, labelsize=7)
ax.collections[0].colorbar.set_label("Pearson r", color=TEXT2, fontsize=8)

# 1c — PCA 2D
ax = fig1.add_subplot(gs1[1, 0])
s_pca = df.sample(4000, random_state=42)
Xs = StandardScaler().fit_transform(s_pca[DISC])
pca = PCA(n_components=2, random_state=42); Xp = pca.fit_transform(Xs)
for label in LABEL_ORDER:
    mask = s_pca["label"].values == label
    if mask.sum()>0:
        ax.scatter(Xp[mask,0],Xp[mask,1],c=COLOR_MAP[label],s=6,alpha=0.55,edgecolors="none",label=label)
style_ax(ax, f"PCA 2D ({pca.explained_variance_ratio_.sum()*100:.1f}% var)", "PC1", "PC2")
ax.legend(fontsize=5.5, loc="upper right", facecolor=BG, edgecolor=GRID, labelcolor=TEXT2, ncol=2, markerscale=1.5)

# 1d — t-SNE 2D
ax = fig1.add_subplot(gs1[1, 1])
s_tsne = df.sample(2500, random_state=42)
Xt = StandardScaler().fit_transform(s_tsne[DISC])
tsne = _tsne_compat(n_components=2, random_state=42, perplexity=40, init="pca")
Xt2 = tsne.fit_transform(Xt)
for label in LABEL_ORDER:
    mask = s_tsne["label"].values == label
    if mask.sum()>0:
        ax.scatter(Xt2[mask,0],Xt2[mask,1],c=COLOR_MAP[label],s=6,alpha=0.6,edgecolors="none")
patches_leg = [mpatches.Patch(color=COLOR_MAP[l],label=l) for l in LABEL_ORDER]
style_ax(ax, "t-SNE 2D (séparabilité non-linéaire)", "dim1", "dim2")
ax.legend(handles=patches_leg, fontsize=5.5, loc="upper right",
          facecolor=BG, edgecolor=GRID, labelcolor=TEXT2, ncol=2, markerscale=1.2)

# 1e — Boxplot flow_pkts_per_sec
ax = fig1.add_subplot(gs1[1, 2])
data_box=[]; labels_box=[]; colors_box=[]
for label in LABEL_ORDER:
    v = df[df["label"]==label]["flow_pkts_per_sec"]
    if len(v) > 0:
        data_box.append(v.clip(0, np.percentile(v,98)))
    else:
        data_box.append(pd.Series([0]))
    labels_box.append(label); colors_box.append(COLOR_MAP[label])
bp = ax.boxplot(data_box, vert=False, patch_artist=True,
                medianprops=dict(color="white",linewidth=1.5),
                whiskerprops=dict(color=TEXT2,linewidth=0.8),
                capprops=dict(color=TEXT2,linewidth=0.8),
                flierprops=dict(marker=".",color=TEXT2,alpha=0.2,markersize=2), widths=0.6)
for patch,c in zip(bp["boxes"],colors_box): patch.set_facecolor(c); patch.set_alpha(0.75)
ax.set_yticks(range(1,len(labels_box)+1))
ax.set_yticklabels(labels_box, color=TEXT2, fontsize=6.5)
style_ax(ax, "Packets/sec par classe (clip p98)", "pkt/s")

# 1f — Heatmap profil normalisé
ax = fig1.add_subplot(gs1[2, 0:2])
HEAT_FEATS = ["flow_pkts_per_sec","flow_iat_mean","syn_flag_count","unique_src_mac",
              "arp_reply_ratio","bcast_ratio","dhcp_offer_count","stp_bpdu_count",
              "has_sql_keyword","has_script_tag","ssl_version_num","session_reuse_ratio",
              "down_up_ratio","http_entropy","pkt_len_mean","fwd_act_data_pkts"]
pivot = df.groupby("label")[HEAT_FEATS].mean().reindex(LABEL_ORDER)
pivot_norm = (pivot-pivot.min())/(pivot.max()-pivot.min()+1e-9)
cmap2 = LinearSegmentedColormap.from_list("bw",["#21262d","#58a6ff","#f0c000"])
sns.heatmap(pivot_norm, ax=ax, cmap=cmap2, linewidths=0.2, linecolor=GRID,
            cbar_kws={"shrink":0.8})
ax.set_facecolor(BG2); ax.tick_params(colors=TEXT2, labelsize=7)
ax.set_title("Fingerprint normalisé par classe (profil moyen)", color=TEXT, fontsize=10, fontweight="bold", pad=8)
ax.set_xticklabels(ax.get_xticklabels(), rotation=40, ha="right", fontsize=7, color=TEXT2)
ax.set_yticklabels(ax.get_yticklabels(), rotation=0, fontsize=7, color=TEXT2)
ax.collections[0].colorbar.ax.tick_params(colors=TEXT2, labelsize=7)

# 1g — ANOVA F-score top 20
ax = fig1.add_subplot(gs1[2, 2])
f_vals, _ = f_classif(X, y)
feat_scores = pd.Series(f_vals, index=FEATURE_COLS).nlargest(20)
bar_c = [ACCENT if i<10 else TEXT2 for i in range(len(feat_scores))]
ax.barh(range(len(feat_scores)), feat_scores.values[::-1],
        color=bar_c[::-1], edgecolor="none", height=0.7)
ax.set_yticks(range(len(feat_scores)))
ax.set_yticklabels(feat_scores.index[::-1], color=TEXT2, fontsize=7)
ax.yaxis.set_tick_params(length=0)
style_ax(ax, "Top 20 features (ANOVA F-score)", "F-score")

fig1.suptitle("IDS ONOS — Visualisation & Analyse de corrélation du dataset",
              color=TEXT, fontsize=14, fontweight="bold", y=0.97)
fig1.savefig("outputs/fig1_correlation_viz.png", dpi=150, bbox_inches="tight", facecolor=BG)
plt.close(fig1)
print("  ✓ fig1_correlation_viz.png")

# ═══════════════════════════ ENTRAÎNEMENT ═══════════════════════════
print("\nTraining models...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s  = scaler.transform(X_test)

# ── FIX XGBoost : re-encoder y en labels consécutifs [0..N-1] ─────────────────
# XGBoost exige des classes CONSÉCUTIVES à partir de 0.
# Si certaines classes sont absentes d'un fold, les indices sautent (ex: 0..7,11,12)
# → ValueError. On remappe proprement une fois pour toutes.
le_consec = LabelEncoder()
y_train_c = le_consec.fit_transform(y_train)   # toujours [0..13] sur le train complet
y_test_c  = le_consec.transform(y_test)

# Mapping consec_idx → original_idx → nom de classe
consec_to_orig  = le_consec.classes_            # consec_to_orig[i] = label original
orig_class_names = le.classes_[consec_to_orig]  # nom des classes dans l'ordre consécutif
N_CLASSES = len(orig_class_names)
ALL_LABELS = list(range(N_CLASSES))
print(f"  Classes remappées consécutivement : {N_CLASSES} classes")
# ──────────────────────────────────────────────────────────────────────────────

MODELS = {
    "Random Forest": RandomForestClassifier(n_estimators=200,n_jobs=-1,random_state=42,min_samples_leaf=2),
    "XGBoost":       XGBClassifier(n_estimators=200,learning_rate=0.1,max_depth=8,
                                    n_jobs=1,random_state=42,eval_metric="mlogloss",verbosity=0),
    "Decision Tree": DecisionTreeClassifier(max_depth=20,random_state=42),
}

results={};  cv_results={}
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

for name, model in MODELS.items():
    t0 = time.time()
    print(f"  [{name}] cross-validating...")
    # XGBoost CV : n_jobs=1 pour éviter les conflits de fork avec ses propres threads
    cv_jobs = 1 if name == "XGBoost" else -1
    cv = cross_validate(model, X_train_s, y_train_c, cv=skf,
                        scoring=["accuracy","f1_macro","precision_macro","recall_macro"],
                        n_jobs=cv_jobs, return_train_score=True)
    cv_results[name] = cv
    print(f"  [{name}] fitting on full train...")
    model.fit(X_train_s, y_train_c)
    y_pred_c = model.predict(X_test_s)

    # Métriques — labels consécutifs, noms originaux
    acc  = accuracy_score(y_test_c, y_pred_c)
    f1   = f1_score(y_test_c, y_pred_c, average="macro",
                    labels=ALL_LABELS, zero_division=0)
    prec = precision_score(y_test_c, y_pred_c, average="macro",
                           labels=ALL_LABELS, zero_division=0)
    rec  = recall_score(y_test_c, y_pred_c, average="macro",
                        labels=ALL_LABELS, zero_division=0)
    cm   = confusion_matrix(y_test_c, y_pred_c, labels=ALL_LABELS)
    cr   = classification_report(y_test_c, y_pred_c,
                                  labels=ALL_LABELS,
                                  target_names=orig_class_names,
                                  output_dict=True,
                                  zero_division=0)

    elapsed = time.time() - t0
    results[name] = {"model":model,"y_pred":y_pred_c,"acc":acc,"f1":f1,
                     "prec":prec,"rec":rec,"cm":cm,"cr":cr,"time":elapsed}
    print(f"    Acc={acc:.4f}  F1={f1:.4f}  CV_F1={cv['test_f1_macro'].mean():.4f}  ({elapsed:.1f}s)")

joblib.dump(results["Random Forest"]["model"], "outputs/model_rf.pkl")
joblib.dump(results["XGBoost"]["model"],        "outputs/model_xgb.pkl")
joblib.dump(scaler,                             "outputs/scaler.pkl")
joblib.dump(le,                                 "outputs/label_encoder.pkl")
print("  ✓ Models + scaler + encoder saved")

# ═══════════════════════════ FIG 2 — TRAINING RESULTS ═══════════════════════════
print("\nBuilding Fig 2 — Training Results...")
fig2 = plt.figure(figsize=(24, 22), facecolor=BG)
gs2  = gridspec.GridSpec(3, 3, figure=fig2, hspace=0.44, wspace=0.35,
                          left=0.06, right=0.97, top=0.93, bottom=0.06)

# 2a — Table métriques
ax = fig2.add_subplot(gs2[0, 0]); ax.set_facecolor(BG2); ax.axis("off")
mdata=[]
for name,r in results.items():
    cv=cv_results[name]
    mdata.append([name, f"{r['acc']:.4f}", f"{r['f1']:.4f}", f"{r['prec']:.4f}", f"{r['rec']:.4f}",
                  f"{cv['test_f1_macro'].mean():.4f}±{cv['test_f1_macro'].std():.4f}", f"{r['time']:.1f}s"])
headers=["Model","Accuracy","F1 macro","Precision","Recall","CV F1 (5-fold)","Time"]
tbl=ax.table(cellText=mdata,colLabels=headers,loc="center",cellLoc="center")
tbl.auto_set_font_size(False); tbl.set_fontsize(7.5); tbl.scale(1.0,2.4)
for j in range(len(headers)):
    tbl[(0,j)].set_facecolor("#1f6feb"); tbl[(0,j)].set_text_props(color=TEXT,fontweight="bold")
row_c=[BG2,"#1a1f27"]
for i in range(1,len(mdata)+1):
    for j in range(len(headers)):
        tbl[(i,j)].set_facecolor(row_c[(i-1)%2])
        tbl[(i,j)].set_text_props(color=TEXT2); tbl[(i,j)].set_edgecolor(GRID)
ax.set_title("Comparaison des modèles", color=TEXT, fontsize=10, fontweight="bold", pad=8)

# 2b — Train vs Val bar
ax = fig2.add_subplot(gs2[0, 1])
x_pos=np.arange(len(MODELS)); bar_w=0.3
for i,(name,col) in enumerate(zip(MODELS.keys(),MCOLS)):
    cv_mean=cv_results[name]["test_f1_macro"].mean(); cv_std=cv_results[name]["test_f1_macro"].std()
    tr_mean=cv_results[name]["train_f1_macro"].mean()
    ax.bar(i-bar_w/2, tr_mean, bar_w, color=col, alpha=0.45, edgecolor="none", label="Train" if i==0 else "")
    ax.bar(i+bar_w/2, cv_mean, bar_w, color=col, alpha=0.95, edgecolor="none", label="Val CV" if i==0 else "")
    ax.errorbar(i+bar_w/2, cv_mean, yerr=cv_std, fmt="none", color="white", capsize=4, linewidth=1.5)
ax.set_xticks(x_pos); ax.set_xticklabels(list(MODELS.keys()), color=TEXT2, fontsize=8)
ax.set_ylim(0.95,1.005)
style_ax(ax, "Train vs Val F1 (5-fold CV)","","F1 macro")
ax.legend(fontsize=8, facecolor=BG, edgecolor=GRID, labelcolor=TEXT2)

# 2c — Métriques CV détaillées
ax = fig2.add_subplot(gs2[0, 2])
metrics_cv=["test_accuracy","test_f1_macro","test_precision_macro","test_recall_macro"]
labels_cv=["Accuracy","F1","Precision","Recall"]
x=np.arange(len(metrics_cv)); width=0.25
for i,(name,col) in enumerate(zip(MODELS.keys(),MCOLS)):
    means=[cv_results[name][m].mean() for m in metrics_cv]
    stds =[cv_results[name][m].std()  for m in metrics_cv]
    ax.bar(x+i*width, means, width, color=col, alpha=0.85, edgecolor="none")
    ax.errorbar(x+i*width, means, yerr=stds, fmt="none", color="white", capsize=3, linewidth=1)
ax.set_xticks(x+width); ax.set_xticklabels(labels_cv, color=TEXT2, fontsize=8)
ax.set_ylim(0.97,1.005)
style_ax(ax,"Métriques CV détaillées","")
ax.legend(handles=[mpatches.Patch(color=c,label=n) for n,c in zip(MODELS.keys(),MCOLS)],
          fontsize=7, facecolor=BG, edgecolor=GRID, labelcolor=TEXT2)

# 2d — Confusion matrix RF
ax = fig2.add_subplot(gs2[1, 0])
cm_norm=results["Random Forest"]["cm"].astype(float)/results["Random Forest"]["cm"].sum(axis=1,keepdims=True)
cmap_cm=LinearSegmentedColormap.from_list("cm",["#161b22","#1f6feb","#58a6ff"])
im=ax.imshow(cm_norm,cmap=cmap_cm,aspect="auto",vmin=0,vmax=1)
ax.set_xticks(range(N_CLASSES)); ax.set_yticks(range(N_CLASSES))
ax.set_xticklabels(orig_class_names,rotation=55,ha="right",fontsize=5.5,color=TEXT2)
ax.set_yticklabels(orig_class_names,fontsize=5.5,color=TEXT2)
for i in range(N_CLASSES):
    for j in range(N_CLASSES):
        v=cm_norm[i,j]
        if v>0.01: ax.text(j,i,f"{v:.2f}",ha="center",va="center",
                           color="white" if v>0.4 else TEXT2, fontsize=5)
plt.colorbar(im,ax=ax,shrink=0.8).ax.tick_params(colors=TEXT2,labelsize=7)
ax.set_facecolor(BG2)
ax.set_title("Confusion matrix — Random Forest (normalisée)",color=TEXT,fontsize=9,fontweight="bold",pad=8)

# 2e — Confusion matrix XGB
ax = fig2.add_subplot(gs2[1, 1])
cm_xgb_n=results["XGBoost"]["cm"].astype(float)/results["XGBoost"]["cm"].sum(axis=1,keepdims=True)
cmap_cm2=LinearSegmentedColormap.from_list("cm2",["#161b22","#b45309","#ffa657"])
im2=ax.imshow(cm_xgb_n,cmap=cmap_cm2,aspect="auto",vmin=0,vmax=1)
ax.set_xticks(range(N_CLASSES)); ax.set_yticks(range(N_CLASSES))
ax.set_xticklabels(orig_class_names,rotation=55,ha="right",fontsize=5.5,color=TEXT2)
ax.set_yticklabels(orig_class_names,fontsize=5.5,color=TEXT2)
for i in range(N_CLASSES):
    for j in range(N_CLASSES):
        v=cm_xgb_n[i,j]
        if v>0.01: ax.text(j,i,f"{v:.2f}",ha="center",va="center",
                           color="white" if v>0.4 else TEXT2, fontsize=5)
plt.colorbar(im2,ax=ax,shrink=0.8).ax.tick_params(colors=TEXT2,labelsize=7)
ax.set_facecolor(BG2)
ax.set_title("Confusion matrix — XGBoost (normalisée)",color=TEXT,fontsize=9,fontweight="bold",pad=8)

# 2f — F1 par classe RF vs XGB
ax = fig2.add_subplot(gs2[1, 2])
cr_rf=results["Random Forest"]["cr"]; cr_xgb=results["XGBoost"]["cr"]
classes_plot=list(orig_class_names)
f1_rf =[cr_rf[c]["f1-score"]  for c in classes_plot]
f1_xgb=[cr_xgb[c]["f1-score"] for c in classes_plot]
x_c=np.arange(len(classes_plot)); w=0.35
ax.barh(x_c-w/2, f1_rf,  w, color="#58a6ff", alpha=0.85, edgecolor="none", label="Random Forest")
ax.barh(x_c+w/2, f1_xgb, w, color="#ffa657", alpha=0.85, edgecolor="none", label="XGBoost")
ax.set_yticks(x_c); ax.set_yticklabels(classes_plot, color=TEXT2, fontsize=7)
ax.set_xlim(0.85,1.02)
style_ax(ax,"F1 par classe — RF vs XGB","F1-score")
ax.legend(fontsize=8, facecolor=BG, edgecolor=GRID, labelcolor=TEXT2)
ax.axvline(1.0, color=GRID, linewidth=0.8, linestyle="--")

# 2g — Feature importances RF
ax = fig2.add_subplot(gs2[2, 0])
importances=pd.Series(results["Random Forest"]["model"].feature_importances_,index=FEATURE_COLS)
top20=importances.nlargest(20)
bar_c2=[ACCENT if i<10 else TEXT2 for i in range(len(top20))]
ax.barh(range(len(top20)), top20.values[::-1], color=bar_c2[::-1], edgecolor="none", height=0.7)
ax.set_yticks(range(len(top20))); ax.set_yticklabels(top20.index[::-1], color=TEXT2, fontsize=7)
ax.yaxis.set_tick_params(length=0)
style_ax(ax,"Feature importances — Random Forest (Top 20)","Importance")

# 2h — Feature importances XGB
ax = fig2.add_subplot(gs2[2, 1])
xgb_imp=pd.Series(results["XGBoost"]["model"].feature_importances_,index=FEATURE_COLS)
top20_xgb=xgb_imp.nlargest(20)
bar_c3=["#ffa657" if i<10 else TEXT2 for i in range(len(top20_xgb))]
ax.barh(range(len(top20_xgb)), top20_xgb.values[::-1], color=bar_c3[::-1], edgecolor="none", height=0.7)
ax.set_yticks(range(len(top20_xgb))); ax.set_yticklabels(top20_xgb.index[::-1], color=TEXT2, fontsize=7)
ax.yaxis.set_tick_params(length=0)
style_ax(ax,"Feature importances — XGBoost (Top 20)","Importance")

# 2i — Learning curve RF
ax = fig2.add_subplot(gs2[2, 2])
rf_lc=RandomForestClassifier(n_estimators=100,n_jobs=-1,random_state=42)
train_sz,train_sc,val_sc=learning_curve(rf_lc,X_train_s,y_train,
    train_sizes=np.linspace(0.1,1.0,8), cv=3, scoring="f1_macro", n_jobs=-1)
ax.plot(train_sz,train_sc.mean(axis=1),color="#58a6ff",linewidth=2,marker="o",markersize=5,label="Train")
ax.fill_between(train_sz,train_sc.mean(axis=1)-train_sc.std(axis=1),
                train_sc.mean(axis=1)+train_sc.std(axis=1),alpha=0.15,color="#58a6ff")
ax.plot(train_sz,val_sc.mean(axis=1),color="#3fb950",linewidth=2,marker="s",markersize=5,label="Val (CV)")
ax.fill_between(train_sz,val_sc.mean(axis=1)-val_sc.std(axis=1),
                val_sc.mean(axis=1)+val_sc.std(axis=1),alpha=0.15,color="#3fb950")
ax.set_ylim(0.92,1.005)
style_ax(ax,"Learning curve — Random Forest (F1 macro)","Samples","F1 macro")
ax.legend(fontsize=8, facecolor=BG, edgecolor=GRID, labelcolor=TEXT2)

fig2.suptitle("IDS ONOS — Entraînement & Validation (80/20 + 5-fold CV)",
              color=TEXT, fontsize=14, fontweight="bold", y=0.97)
fig2.savefig("outputs/fig2_training_results.png", dpi=150, bbox_inches="tight", facecolor=BG)
plt.close(fig2)
print("  ✓ fig2_training_results.png")

# ═══════════════════════════ FIG 3 — PER-CLASS REPORT ═══════════════════════════
print("\nBuilding Fig 3 — Per-class report...")
fig3, axes = plt.subplots(1,3, figsize=(22,9), facecolor=BG)
for ax_idx,(name,col) in enumerate(zip(["Random Forest","XGBoost","Decision Tree"],MCOLS)):
    ax=axes[ax_idx]; ax.set_facecolor(BG2)
    cr=results[name]["cr"]; classes_r=list(orig_class_names)
    metrics_r=["precision","recall","f1-score"]
    data_r=np.array([[cr[c][m] for c in classes_r] for m in metrics_r]).T
    x_r=np.arange(len(classes_r)); w_r=0.26
    for mi,(metric,bc) in enumerate(zip(metrics_r,["#58a6ff","#ffa657","#3fb950"])):
        ax.bar(x_r+mi*w_r, data_r[:,mi], w_r, color=bc, alpha=0.85, edgecolor="none", label=metric.capitalize())
    ax.set_xticks(x_r+w_r); ax.set_xticklabels(classes_r,rotation=50,ha="right",fontsize=7,color=TEXT2)
    ax.set_ylim(0.85,1.02); ax.axhline(1.0,color=GRID,linewidth=0.8,linestyle="--")
    style_ax(ax,f"{name}\nAcc={results[name]['acc']:.4f}  F1={results[name]['f1']:.4f}","")
    ax.legend(fontsize=8, facecolor=BG, edgecolor=GRID, labelcolor=TEXT2)
fig3.suptitle("Rapport détaillé par classe — Precision / Recall / F1",
              color=TEXT, fontsize=13, fontweight="bold", y=1.01)
plt.tight_layout()
fig3.savefig("outputs/fig3_per_class_report.png", dpi=150, bbox_inches="tight", facecolor=BG)
plt.close(fig3)
print("  ✓ fig3_per_class_report.png")

# ═══════════════════════════ SUMMARY JSON ═══════════════════════════
summary={}
for name,r in results.items():
    cv=cv_results[name]
    summary[name]={
        "test_accuracy":  round(r["acc"],5), "test_f1_macro": round(r["f1"],5),
        "test_precision": round(r["prec"],5),"test_recall":   round(r["rec"],5),
        "cv_f1_mean":     round(float(cv["test_f1_macro"].mean()),5),
        "cv_f1_std":      round(float(cv["test_f1_macro"].std()),5),
        "training_time_s":round(r["time"],2),
    }
with open("outputs/training_summary.json","w") as f:
    json.dump(summary,f,indent=2)
print("  ✓ training_summary.json")

print("\n══ RÉSUMÉ FINAL ══")
for name,r in results.items():
    cv=cv_results[name]
    print(f"  {name:<20} Acc={r['acc']:.4f}  F1={r['f1']:.4f}  CV={cv['test_f1_macro'].mean():.4f}±{cv['test_f1_macro'].std():.4f}  ({r['time']:.1f}s)")
