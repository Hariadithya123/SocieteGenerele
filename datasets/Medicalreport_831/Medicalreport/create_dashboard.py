import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.patches import FancyBboxPatch
from matplotlib import patheffects
from sqlalchemy import create_engine
from urllib.parse import quote_plus
import joblib
import warnings
warnings.filterwarnings('ignore')

# ---- Database Connection ----
username = 'root'
password = quote_plus('Baala@1975')
host = 'localhost'
database = 'medical_lab_db'
engine = create_engine(f'mysql+pymysql://{username}:{password}@{host}/{database}')

print("Loading data from MySQL...")
df_sample = pd.read_sql("SELECT * FROM sample_id", engine)
df_equip = pd.read_sql("SELECT * FROM equipment_id", engine)
df_reagent = pd.read_sql("SELECT * FROM reagent_id", engine)
df_reject = pd.read_sql("SELECT * FROM rejection_id", engine)

# ---- Preprocessing ----
df_sample['COLLECTION TIME'] = pd.to_datetime(df_sample['COLLECTION TIME'])
df_sample['REPORT RELEASE TIME'] = pd.to_datetime(df_sample['REPORT RELEASE TIME'], errors='coerce')
df_sample['PROCESSING START TIME'] = pd.to_datetime(df_sample['PROCESSING START TIME'])
df_sample['PROCESSING END TIME'] = pd.to_datetime(df_sample['PROCESSING END TIME'])

completed = df_sample[df_sample['STATUS'].isin(['Completed', 'Delayed'])].copy()
completed['TAT_hours'] = (completed['REPORT RELEASE TIME'] - completed['COLLECTION TIME']).dt.total_seconds() / 3600.0

# ---- Load ML Model ----
model = joblib.load('c:/Users/Baalamuruga Y K/Downloads/Medicalreport/tat_prediction_model.pkl')
completed['collection_hour'] = completed['COLLECTION TIME'].dt.hour
completed['collection_dayofweek'] = completed['COLLECTION TIME'].dt.dayofweek
X_pred = completed[['DEPARTMENT', 'TEST NAME', 'collection_hour', 'collection_dayofweek']]
completed['Predicted_TAT_hours'] = model.predict(X_pred) / 60.0

# ---- Color Palette ----
BG_DARK = '#0f1117'
CARD_BG = '#1a1d2e'
ACCENT_BLUE = '#4fc3f7'
ACCENT_GREEN = '#66bb6a'
ACCENT_ORANGE = '#ffa726'
ACCENT_RED = '#ef5350'
ACCENT_PURPLE = '#ab47bc'
ACCENT_CYAN = '#26c6da'
TEXT_WHITE = '#e0e0e0'
TEXT_GRAY = '#9e9e9e'
GRID_COLOR = '#2a2d3e'

dept_colors = ['#4fc3f7', '#66bb6a', '#ffa726', '#ef5350', '#ab47bc', '#26c6da']
status_colors = {'Completed': '#66bb6a', 'In Progress': '#ffa726', 'Pending': '#4fc3f7', 'Delayed': '#ef5350'}
reject_colors = {'ACCEPTED': '#66bb6a', 'REJECTED': '#ef5350'}
stock_colors = {'AVAILABLE': '#66bb6a', 'LOW': '#ffa726', 'OUT OF STOCK': '#ef5350', 'EXPIRED': '#ab47bc'}
failure_colors = ['#4fc3f7', '#ffa726', '#ef5350', '#66bb6a', '#ab47bc', '#26c6da']

# ======== PAGE 1: OVERVIEW DASHBOARD ========
print("Creating Page 1: Overview Dashboard...")
fig = plt.figure(figsize=(24, 16), facecolor=BG_DARK)
fig.suptitle('', y=0.99)

gs = gridspec.GridSpec(4, 4, figure=fig, hspace=0.35, wspace=0.3,
                       left=0.04, right=0.96, top=0.92, bottom=0.04)

# ---- Title Bar ----
title_ax = fig.add_axes([0.04, 0.93, 0.92, 0.06])
title_ax.set_facecolor(BG_DARK)
title_ax.axis('off')
title_ax.text(0.5, 0.6, '🏥  MEDICAL LABORATORY PERFORMANCE DASHBOARD',
              ha='center', va='center', fontsize=26, fontweight='bold',
              color=ACCENT_CYAN, fontfamily='sans-serif',
              path_effects=[patheffects.withSimplePatchShadow(offset=(2, -2), shadow_rgbFace='black', alpha=0.3)])
title_ax.text(0.5, 0.1, 'Real-time Analytics  •  AI-Powered Predictions  •  Operational Intelligence',
              ha='center', va='center', fontsize=12, color=TEXT_GRAY, fontfamily='sans-serif')

# ---- KPI Cards (Row 0) ----
kpi_data = [
    ('Total Samples', f"{len(df_sample):,}", ACCENT_BLUE, '📊'),
    ('Avg TAT (Hours)', f"{completed['TAT_hours'].mean():.1f}", ACCENT_GREEN, '⏱️'),
    ('Equipment Failures', f"{(df_equip['FAILURE STATUS']=='YES').sum():,}", ACCENT_ORANGE, '⚠️'),
    ('Rejection Rate', f"{(df_reject['STATUS']=='REJECTED').mean()*100:.1f}%", ACCENT_RED, '❌'),
]

for i, (title, value, color, icon) in enumerate(kpi_data):
    ax = fig.add_subplot(gs[0, i])
    ax.set_facecolor(CARD_BG)
    for spine in ax.spines.values():
        spine.set_edgecolor(color)
        spine.set_linewidth(2)
    ax.set_xticks([])
    ax.set_yticks([])
    ax.text(0.5, 0.72, f"{icon} {value}", ha='center', va='center',
            fontsize=28, fontweight='bold', color=color, transform=ax.transAxes)
    ax.text(0.5, 0.25, title.upper(), ha='center', va='center',
            fontsize=11, color=TEXT_GRAY, fontweight='bold', transform=ax.transAxes, fontfamily='sans-serif')

# ---- Chart 1: Sample Status Distribution (Row 1, Col 0-1) ----
ax1 = fig.add_subplot(gs[1, 0:2])
ax1.set_facecolor(CARD_BG)
status_counts = df_sample['STATUS'].value_counts()
colors_list = [status_colors.get(s, '#999999') for s in status_counts.index]
wedges, texts, autotexts = ax1.pie(status_counts.values, labels=status_counts.index,
                                     autopct='%1.1f%%', colors=colors_list, startangle=90,
                                     textprops={'color': TEXT_WHITE, 'fontsize': 11},
                                     pctdistance=0.8, wedgeprops=dict(width=0.4, edgecolor=BG_DARK, linewidth=2))
for autotext in autotexts:
    autotext.set_fontsize(10)
    autotext.set_fontweight('bold')
ax1.set_title('SAMPLE STATUS DISTRIBUTION', color=ACCENT_CYAN, fontsize=13, fontweight='bold', pad=15)

# ---- Chart 2: Avg TAT by Department (Row 1, Col 2-3) ----
ax2 = fig.add_subplot(gs[1, 2:4])
ax2.set_facecolor(CARD_BG)
dept_tat = completed.groupby('DEPARTMENT')['TAT_hours'].mean().sort_values(ascending=True)
bars = ax2.barh(dept_tat.index, dept_tat.values, color=dept_colors[:len(dept_tat)], edgecolor='none', height=0.6)
for bar, val in zip(bars, dept_tat.values):
    ax2.text(val + 0.3, bar.get_y() + bar.get_height()/2, f'{val:.1f}h',
             va='center', ha='left', color=TEXT_WHITE, fontsize=10, fontweight='bold')
ax2.set_xlabel('Average Turnaround Time (Hours)', color=TEXT_GRAY, fontsize=10)
ax2.set_title('AVG TURNAROUND TIME BY DEPARTMENT', color=ACCENT_CYAN, fontsize=13, fontweight='bold', pad=15)
ax2.tick_params(colors=TEXT_GRAY)
ax2.set_facecolor(CARD_BG)
ax2.spines['bottom'].set_color(GRID_COLOR)
ax2.spines['left'].set_color(GRID_COLOR)
ax2.spines['top'].set_visible(False)
ax2.spines['right'].set_visible(False)
ax2.xaxis.grid(True, color=GRID_COLOR, alpha=0.3)

# ---- Chart 3: Equipment Failure Reasons (Row 2, Col 0-1) ----
ax3 = fig.add_subplot(gs[2, 0:2])
ax3.set_facecolor(CARD_BG)
failures = df_equip[df_equip['FAILURE STATUS'] == 'YES']
fail_counts = failures['FAILURE REASON'].value_counts()
wedges3, texts3, autotexts3 = ax3.pie(fail_counts.values, labels=fail_counts.index,
                                        autopct='%1.1f%%', colors=failure_colors[:len(fail_counts)],
                                        startangle=140,
                                        textprops={'color': TEXT_WHITE, 'fontsize': 9},
                                        pctdistance=0.8, wedgeprops=dict(width=0.45, edgecolor=BG_DARK, linewidth=2))
for autotext in autotexts3:
    autotext.set_fontsize(9)
    autotext.set_fontweight('bold')
ax3.set_title('EQUIPMENT FAILURE REASONS', color=ACCENT_ORANGE, fontsize=13, fontweight='bold', pad=15)

# ---- Chart 4: Reagent Stock Status (Row 2, Col 2-3) ----
ax4 = fig.add_subplot(gs[2, 2:4])
ax4.set_facecolor(CARD_BG)
stock_counts = df_reagent['STOCK STATUS'].value_counts()
sc_colors = [stock_colors.get(s, '#999999') for s in stock_counts.index]
bars4 = ax4.bar(stock_counts.index, stock_counts.values, color=sc_colors, edgecolor='none', width=0.5)
for bar, val in zip(bars4, stock_counts.values):
    ax4.text(bar.get_x() + bar.get_width()/2, val + 50, f'{val:,}',
             ha='center', va='bottom', color=TEXT_WHITE, fontsize=11, fontweight='bold')
ax4.set_title('REAGENT STOCK STATUS', color=ACCENT_GREEN, fontsize=13, fontweight='bold', pad=15)
ax4.tick_params(colors=TEXT_GRAY)
ax4.spines['bottom'].set_color(GRID_COLOR)
ax4.spines['left'].set_color(GRID_COLOR)
ax4.spines['top'].set_visible(False)
ax4.spines['right'].set_visible(False)
ax4.yaxis.grid(True, color=GRID_COLOR, alpha=0.3)

# ---- Chart 5: Rejection Analysis (Row 3, Col 0-1) ----
ax5 = fig.add_subplot(gs[3, 0:2])
ax5.set_facecolor(CARD_BG)
rej_by_reason = df_reject[df_reject['STATUS'] == 'REJECTED']['REJECTION REASON'].value_counts()
bars5 = ax5.barh(rej_by_reason.index, rej_by_reason.values,
                 color=[ACCENT_RED, ACCENT_ORANGE, ACCENT_PURPLE, '#26c6da', '#ffca28', '#8d6e63', '#78909c'][:len(rej_by_reason)],
                 edgecolor='none', height=0.55)
for bar, val in zip(bars5, rej_by_reason.values):
    ax5.text(val + 10, bar.get_y() + bar.get_height()/2, f'{val:,}',
             va='center', ha='left', color=TEXT_WHITE, fontsize=10, fontweight='bold')
ax5.set_title('TOP REJECTION REASONS', color=ACCENT_RED, fontsize=13, fontweight='bold', pad=15)
ax5.tick_params(colors=TEXT_GRAY)
ax5.spines['bottom'].set_color(GRID_COLOR)
ax5.spines['left'].set_color(GRID_COLOR)
ax5.spines['top'].set_visible(False)
ax5.spines['right'].set_visible(False)
ax5.xaxis.grid(True, color=GRID_COLOR, alpha=0.3)

# ---- Chart 6: AI Predicted vs Actual TAT (Row 3, Col 2-3) ----
ax6 = fig.add_subplot(gs[3, 2:4])
ax6.set_facecolor(CARD_BG)
dept_compare = completed.groupby('DEPARTMENT').agg(
    Actual=('TAT_hours', 'mean'),
    Predicted=('Predicted_TAT_hours', 'mean')
).reset_index()
x_pos = np.arange(len(dept_compare))
w = 0.35
bars_actual = ax6.bar(x_pos - w/2, dept_compare['Actual'], w, color=ACCENT_BLUE, label='Actual TAT', edgecolor='none')
bars_pred = ax6.bar(x_pos + w/2, dept_compare['Predicted'], w, color=ACCENT_GREEN, label='AI Predicted TAT', edgecolor='none')
ax6.set_xticks(x_pos)
ax6.set_xticklabels(dept_compare['DEPARTMENT'], rotation=25, ha='right', fontsize=9)
ax6.legend(loc='upper right', fontsize=9, facecolor=CARD_BG, edgecolor=GRID_COLOR, labelcolor=TEXT_WHITE)
ax6.set_title('🤖 AI PREDICTED vs ACTUAL TAT (HOURS)', color=ACCENT_GREEN, fontsize=13, fontweight='bold', pad=15)
ax6.tick_params(colors=TEXT_GRAY)
ax6.spines['bottom'].set_color(GRID_COLOR)
ax6.spines['left'].set_color(GRID_COLOR)
ax6.spines['top'].set_visible(False)
ax6.spines['right'].set_visible(False)
ax6.yaxis.grid(True, color=GRID_COLOR, alpha=0.3)
ax6.set_ylabel('Hours', color=TEXT_GRAY, fontsize=10)

# ---- Save Page 1 ----
output1 = 'c:/Users/Baalamuruga Y K/Downloads/Medicalreport/Dashboard_Page1_Overview.png'
plt.savefig(output1, dpi=150, facecolor=BG_DARK, bbox_inches='tight')
plt.close()
print(f"Page 1 saved: {output1}")


# ======== PAGE 2: DETAILED ANALYTICS ========
print("Creating Page 2: Detailed Analytics...")
fig2 = plt.figure(figsize=(24, 16), facecolor=BG_DARK)
gs2 = gridspec.GridSpec(3, 3, figure=fig2, hspace=0.35, wspace=0.3,
                        left=0.05, right=0.96, top=0.91, bottom=0.05)

# Title
title_ax2 = fig2.add_axes([0.04, 0.92, 0.92, 0.06])
title_ax2.set_facecolor(BG_DARK)
title_ax2.axis('off')
title_ax2.text(0.5, 0.6, '📈  DETAILED ANALYTICS & TRENDS',
               ha='center', va='center', fontsize=26, fontweight='bold',
               color=ACCENT_CYAN, fontfamily='sans-serif',
               path_effects=[patheffects.withSimplePatchShadow(offset=(2, -2), shadow_rgbFace='black', alpha=0.3)])

# ---- Chart 7: Monthly Sample Volume Trend ----
ax7 = fig2.add_subplot(gs2[0, :])
ax7.set_facecolor(CARD_BG)
df_sample['month'] = df_sample['COLLECTION TIME'].dt.to_period('M')
monthly = df_sample.groupby('month').size()
ax7.fill_between(range(len(monthly)), monthly.values, alpha=0.3, color=ACCENT_BLUE)
ax7.plot(range(len(monthly)), monthly.values, color=ACCENT_BLUE, linewidth=2.5, marker='o', markersize=5)
ax7.set_xticks(range(0, len(monthly), max(1, len(monthly)//12)))
ax7.set_xticklabels([str(monthly.index[i]) for i in range(0, len(monthly), max(1, len(monthly)//12))], rotation=30, ha='right')
ax7.set_title('MONTHLY SAMPLE VOLUME TREND', color=ACCENT_CYAN, fontsize=14, fontweight='bold', pad=15)
ax7.tick_params(colors=TEXT_GRAY)
ax7.spines['bottom'].set_color(GRID_COLOR)
ax7.spines['left'].set_color(GRID_COLOR)
ax7.spines['top'].set_visible(False)
ax7.spines['right'].set_visible(False)
ax7.yaxis.grid(True, color=GRID_COLOR, alpha=0.3)
ax7.set_ylabel('Number of Samples', color=TEXT_GRAY, fontsize=10)

# ---- Chart 8: Test Volume by Department ----
ax8 = fig2.add_subplot(gs2[1, 0])
ax8.set_facecolor(CARD_BG)
dept_counts = df_sample['DEPARTMENT'].value_counts()
wedges8, texts8, autotexts8 = ax8.pie(dept_counts.values, labels=dept_counts.index,
                                        autopct='%1.1f%%', colors=dept_colors,
                                        textprops={'color': TEXT_WHITE, 'fontsize': 9},
                                        pctdistance=0.8, wedgeprops=dict(width=0.4, edgecolor=BG_DARK, linewidth=2))
for at in autotexts8:
    at.set_fontsize(8)
    at.set_fontweight('bold')
ax8.set_title('TEST VOLUME BY DEPT', color=ACCENT_CYAN, fontsize=12, fontweight='bold', pad=10)

# ---- Chart 9: Equipment Downtime by Equipment ----
ax9 = fig2.add_subplot(gs2[1, 1:3])
ax9.set_facecolor(CARD_BG)
downtime = df_equip[df_equip['DOWN TIME (MIN)'] > 0].groupby('EQUIPMENT NAME')['DOWN TIME (MIN)'].sum().sort_values(ascending=True).tail(10)
bars9 = ax9.barh(downtime.index, downtime.values, color=ACCENT_ORANGE, edgecolor='none', height=0.6)
for bar, val in zip(bars9, downtime.values):
    ax9.text(val + 5, bar.get_y() + bar.get_height()/2, f'{val:,} min',
             va='center', ha='left', color=TEXT_WHITE, fontsize=9, fontweight='bold')
ax9.set_title('TOP 10 EQUIPMENT BY TOTAL DOWNTIME (MINUTES)', color=ACCENT_ORANGE, fontsize=12, fontweight='bold', pad=15)
ax9.tick_params(colors=TEXT_GRAY)
ax9.spines['bottom'].set_color(GRID_COLOR)
ax9.spines['left'].set_color(GRID_COLOR)
ax9.spines['top'].set_visible(False)
ax9.spines['right'].set_visible(False)
ax9.xaxis.grid(True, color=GRID_COLOR, alpha=0.3)

# ---- Chart 10: TAT Distribution by Hour of Day ----
ax10 = fig2.add_subplot(gs2[2, 0:2])
ax10.set_facecolor(CARD_BG)
completed['hour'] = completed['COLLECTION TIME'].dt.hour
hourly_tat = completed.groupby('hour')['TAT_hours'].mean()
ax10.fill_between(hourly_tat.index, hourly_tat.values, alpha=0.3, color=ACCENT_GREEN)
ax10.plot(hourly_tat.index, hourly_tat.values, color=ACCENT_GREEN, linewidth=2.5, marker='o', markersize=6)
ax10.set_xlabel('Hour of Day (24h format)', color=TEXT_GRAY, fontsize=10)
ax10.set_ylabel('Avg TAT (Hours)', color=TEXT_GRAY, fontsize=10)
ax10.set_title('AVG TURNAROUND TIME BY HOUR OF DAY', color=ACCENT_GREEN, fontsize=12, fontweight='bold', pad=15)
ax10.tick_params(colors=TEXT_GRAY)
ax10.spines['bottom'].set_color(GRID_COLOR)
ax10.spines['left'].set_color(GRID_COLOR)
ax10.spines['top'].set_visible(False)
ax10.spines['right'].set_visible(False)
ax10.yaxis.grid(True, color=GRID_COLOR, alpha=0.3)

# ---- Chart 11: Rejection by Department ----
ax11 = fig2.add_subplot(gs2[2, 2])
ax11.set_facecolor(CARD_BG)
rej_dept = df_reject[df_reject['STATUS'] == 'REJECTED'].groupby('DEPARTMENT').size().sort_values(ascending=True)
bars11 = ax11.barh(rej_dept.index, rej_dept.values, color=ACCENT_RED, edgecolor='none', height=0.5)
for bar, val in zip(bars11, rej_dept.values):
    ax11.text(val + 5, bar.get_y() + bar.get_height()/2, f'{val:,}',
              va='center', ha='left', color=TEXT_WHITE, fontsize=9, fontweight='bold')
ax11.set_title('REJECTIONS BY DEPT', color=ACCENT_RED, fontsize=12, fontweight='bold', pad=15)
ax11.tick_params(colors=TEXT_GRAY)
ax11.spines['bottom'].set_color(GRID_COLOR)
ax11.spines['left'].set_color(GRID_COLOR)
ax11.spines['top'].set_visible(False)
ax11.spines['right'].set_visible(False)
ax11.xaxis.grid(True, color=GRID_COLOR, alpha=0.3)

output2 = 'c:/Users/Baalamuruga Y K/Downloads/Medicalreport/Dashboard_Page2_Analytics.png'
plt.savefig(output2, dpi=150, facecolor=BG_DARK, bbox_inches='tight')
plt.close()
print(f"Page 2 saved: {output2}")

print("\n✅ Dashboard generation complete!")
print("Files saved:")
print(f"  1. {output1}")
print(f"  2. {output2}")
