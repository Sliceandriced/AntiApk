import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl


permission_count = ctrl.Antecedent(np.arange(0, 21, 1), 'Permission Count')
virus_total_score = ctrl.Antecedent(np.arange(0, 61, 1), 'Virus total vendors')
permission_risk = ctrl.Antecedent(np.arange(0, 101, 1), 'Permission Risk')

risk_score = ctrl.Consequent(np.arange(0, 101, 1), 'Risk Score')

#input variables
permission_count['Low'] = fuzz.trapmf(permission_count.universe, [0, 0, 4, 5])
permission_count['Medium'] = fuzz.trapmf(permission_count.universe, [4, 6, 8, 10])
permission_count['High'] = fuzz.trapmf(permission_count.universe, [8, 10, 20, 20])

virus_total_score['None'] = fuzz.trapmf(virus_total_score.universe, [0, 0, 0, 0])
virus_total_score['Medium'] = fuzz.trimf(virus_total_score.universe, [1, 5, 6])
virus_total_score['High'] = fuzz.trapmf(virus_total_score.universe, [5, 6, 60, 60])

permission_risk['Low Score'] = fuzz.trapmf(permission_risk.universe, [0, 0, 30, 40])
permission_risk['Medium Score'] = fuzz.trapmf(permission_risk.universe, [30, 40, 60, 70])
permission_risk['High'] = fuzz.trapmf(permission_risk.universe, [60, 70, 100, 100])

#output variable
risk_score['Low Risk'] = fuzz.trapmf(risk_score.universe, [0, 0, 30, 40])
risk_score['Medium Risk'] = fuzz.trapmf(risk_score.universe, [30, 40, 60, 70])
risk_score['High Risk'] = fuzz.trapmf(risk_score.universe, [60, 70, 100, 100])

#
rule1 = ctrl.Rule(permission_count['Low'] & virus_total_score['None'] & permission_risk['Low Score'], risk_score['Low Risk'])
rule2 = ctrl.Rule(permission_count['Low'] & virus_total_score['None'] & permission_risk['Medium Score'], risk_score['Low Risk'])
rule3 = ctrl.Rule(permission_count['Low'] & virus_total_score['None'] & permission_risk['High'], risk_score['Medium Risk'])
rule4 = ctrl.Rule(permission_count['Low'] & virus_total_score['Medium'] & permission_risk['Low Score'], risk_score['Medium Risk'])
rule5 = ctrl.Rule(permission_count['Low'] & virus_total_score['Medium'] & permission_risk['Medium Score'], risk_score['Medium Risk'])
rule6 = ctrl.Rule(permission_count['Low'] & virus_total_score['Medium'] & permission_risk['High'], risk_score['Medium Risk'])
rule7 = ctrl.Rule(permission_count['Low'] & virus_total_score['High'] & permission_risk['Low Score'], risk_score['High Risk'])
rule8 = ctrl.Rule(permission_count['Low'] & virus_total_score['High'] & permission_risk['Medium Score'], risk_score['High Risk'])
rule9 = ctrl.Rule(permission_count['Low'] & virus_total_score['High'] & permission_risk['High'], risk_score['High Risk'])
rule10 = ctrl.Rule(permission_count['Medium'] & virus_total_score['None'] & permission_risk['Low Score'], risk_score['Low Risk'])
rule11 = ctrl.Rule(permission_count['Medium'] & virus_total_score['None'] & permission_risk['Medium Score'], risk_score['Medium Risk'])
rule12 = ctrl.Rule(permission_count['Medium'] & virus_total_score['None'] & permission_risk['High'], risk_score['Medium Risk'])
rule13 = ctrl.Rule(permission_count['Medium'] & virus_total_score['Medium'] & permission_risk['Low Score'], risk_score['Low Risk'])
rule14 = ctrl.Rule(permission_count['Medium'] & virus_total_score['Medium'] & permission_risk['Medium Score'], risk_score['Low Risk'])
rule15 = ctrl.Rule(permission_count['Medium'] & virus_total_score['Medium'] & permission_risk['High'], risk_score['High Risk'])
rule16 = ctrl.Rule(permission_count['Medium'] & virus_total_score['High'] & permission_risk['Low Score'], risk_score['High Risk'])
rule17 = ctrl.Rule(permission_count['Medium'] & virus_total_score['High'] & permission_risk['Medium Score'], risk_score['High Risk'])
rule18 = ctrl.Rule(permission_count['Medium'] & virus_total_score['High'] & permission_risk['High'], risk_score['High Risk'])
rule19 = ctrl.Rule(permission_count['High'] & virus_total_score['None'] & permission_risk['Low Score'], risk_score['Medium Risk'])
rule20 = ctrl.Rule(permission_count['High'] & virus_total_score['None'] & permission_risk['Medium Score'], risk_score['Medium Risk'])
rule21 = ctrl.Rule(permission_count['High'] & virus_total_score['None'] & permission_risk['High'], risk_score['High Risk'])
rule22 = ctrl.Rule(permission_count['High'] & virus_total_score['Medium'] & permission_risk['Low Score'], risk_score['Medium Risk'])
rule23 = ctrl.Rule(permission_count['High'] & virus_total_score['Medium'] & permission_risk['Medium Score'], risk_score['Medium Risk'])
rule24 = ctrl.Rule(permission_count['High'] & virus_total_score['Medium'] & permission_risk['High'], risk_score['High Risk'])
rule25 = ctrl.Rule(permission_count['High'] & virus_total_score['High'] & permission_risk['Low Score'], risk_score['Medium Risk'])
rule26 = ctrl.Rule(permission_count['High'] & virus_total_score['High'] & permission_risk['Medium Score'], risk_score['Medium Risk'])
rule27 = ctrl.Rule(permission_count['High'] & virus_total_score['High'] & permission_risk['High'], risk_score['High Risk'])

#rule set
risk_analysis_ctrl = ctrl.ControlSystem([rule1, rule2, rule3, rule4, rule5, rule6, rule7, rule8, rule9,
            rule10, rule11, rule12, rule13, rule14, rule15, rule16, rule17, rule18,
            rule19, rule20, rule21, rule22, rule23, rule24, rule25, rule26, rule27])

risk_analysis = ctrl.ControlSystemSimulation(risk_analysis_ctrl)

#input values
input_file = open("Risk.txt","r")
input_data = input_file.readlines()                                                                                                            
risk_analysis.input['Permission Count'] = int(input_data[0])
risk_analysis.input['Virus total vendors'] = int(input_data[1])
risk_analysis.input['Permission Risk'] = int(input_data[2])
input_file.close()

# Compute output
risk_analysis.compute()

# Print output
print(risk_analysis.output['Risk Score'])
input_file = open("Risk.txt","w")
input_file.write(str(risk_analysis.output['Risk Score']))
input_file.close()
